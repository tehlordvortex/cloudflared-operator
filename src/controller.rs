use std::{
    collections::BTreeMap,
    fmt::Debug,
    hash::{DefaultHasher, Hash, Hasher},
    iter,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use cloudflare::endpoints::cfd_tunnel::{
    self, create_tunnel, delete_tunnel, list_tunnels, update_tunnel,
};
use k8s_openapi::{
    DeepMerge,
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{
            Affinity, Capabilities, ConfigMap, ConfigMapVolumeSource, Container, EnvVar,
            EnvVarSource, HTTPGetAction, HostAlias, LocalObjectReference, NodeAffinity,
            NodeSelector, NodeSelectorRequirement, NodeSelectorTerm, PodDNSConfig,
            PodSecurityContext, PodSpec, PodTemplateSpec, Probe, ResourceFieldSelector,
            SeccompProfile, Secret, SecretVolumeSource, SecurityContext, Toleration,
            TopologySpreadConstraint, Volume, VolumeMount,
        },
        discovery::v1::EndpointSlice,
    },
    apimachinery::pkg::{
        apis::meta::v1::{Condition, LabelSelector},
        util::intstr::IntOrString,
    },
};
use kube::{
    Api, CustomResource, KubeSchema, Resource, ResourceExt,
    api::{DeleteParams, ListParams, ObjectMeta, PartialObjectMeta, Patch, PatchParams},
    core::Selector,
    runtime::{controller::Action, finalizer, reflector},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use serde_with::{base64::Base64, serde_as};
use tracing::{debug, error, instrument, trace};

use crate::{Error, Result, WatchNamespace};

/// Manages a cloudflared tunnel and its replicas for a particular service
#[derive(CustomResource, Serialize, Deserialize, Debug, PartialEq, Clone, JsonSchema)]
#[kube(
    group = "cloudflared-operator.vrtx.sh",
    version = "v1alpha1",
    kind = "CfdTunnel",
    plural = "cfdtunnels",
    derive = "PartialEq",
    status = "CfdTunnelStatus",
    namespaced
)]
pub struct CfdTunnelSpec {
    /// The Account ID under which the tunnel will be created
    #[serde(rename = "accountId")]
    pub account_id: String,
    /// The secret containing the API token that will be used to manage this tunnel.
    /// Must have sufficient permissions to manage cloudflared Tunnels on the account.
    /// IMPORTANT: Must NOT be deleted BEFORE the tunnel, otherwise the tunnel will
    /// never finalize.
    #[serde(rename = "apiToken")]
    pub api_token: CfdTunnelApiToken,
    /// The service whose endpoint slices are used to identify nodes serving traffic
    /// for the workload. Consequently, cloudflared instances will be scheduled to them.
    /// Namespace is optional and defaults to the same namespace as the CfdTunnel.
    #[serde(rename = "serviceRef")]
    pub service_ref: CfdTunnelRef,
    /// Ingress rules that configure how traffic gets routed once it hits
    /// cloudflared. The hostnames here are not automatically configured as
    /// DNS records.
    pub ingress: Vec<CfdTunnelIngressRule>,
    /// Customize the request sent by cloudflared to your origin.
    /// May be overriden per-ingress.
    /// Accepts a YAML string of the fields as described in the documentation:
    /// https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/
    #[serde(rename = "originRequestConfig")]
    pub origin_request_config: Option<String>,
    /// The log level for cloudflared. Defaults to "info".
    #[serde(rename = "logLevel", default = "default_log_level")]
    pub log_level: String,
    /// The protocol used by cloudflared. Defaults to "auto".
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// The protocol used by cloudflared. Defaults to "0.0.0.0:2000".
    /// Also used to configure a livenessProbe for the container.
    #[serde(rename = "metricsAddr", default = "default_metrics_addr")]
    pub metrics_addr: String,
    /// If present, enables DNS configuration with External DNS.
    /// This supports the dnsendpoints.externaldns.k8s.io/v1alpha1 CRD, which must
    /// be present in the cluster.
    /// See https://kubernetes-sigs.github.io/external-dns/latest/docs/sources/crd
    pub dns: Option<CfdTunnelDns>,
    /// Override some fields in the pod definition.
    /// This is merged into the generated definition and takes higher priority.
    /// See also "container_overrides" and "additional_containers".
    #[serde(rename = "podSpecOverrides")]
    pub pod_spec_overrides: Option<CfdTunnelPodOverrides>,
    /// Override fields in the cloudflared container definition.
    /// This is merged into the generated definition and takes higher priority.
    #[serde(rename = "containerOverrides")]
    pub container_overrides: Option<Container>,
    /// Add additional containers to the pod
    #[serde(rename = "additionalContainers")]
    pub additional_containers: Option<Vec<Container>>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct CfdTunnelStatus {
    /// Cloudflare Tunnel ID
    #[serde(rename = "tunnelId")]
    pub tunnel_id: Option<String>,
    /// Contains only one condition, Ready, which is set to True
    /// once the tunnel has been configured on Cloudflare
    pub conditions: Vec<Condition>,
    #[serde(rename = "dnsEndpointNamespace")]
    pub dns_endpoint_namespace: Option<String>,
}

fn default_log_level() -> String {
    "info".into()
}

fn default_protocol() -> String {
    "auto".into()
}

fn default_metrics_addr() -> String {
    "0.0.0.0:2000".into()
}

/// Defines how traffic is routed by cloudflared
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CfdTunnelIngressRule {
    /// The service to proxy requests to.
    /// See https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/protocols
    /// for supported protocols. This is really only intended for use with HTTP(s), though.
    pub service: String,
    pub hostname: Option<String>,
    pub path: Option<String>,
    #[serde(rename = "originRequestConfig")]
    pub origin_request_config: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, KubeSchema)]
pub struct CfdTunnelRef {
    #[x_kube(validation = ("self != ''", "name must be set"))]
    pub name: String,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CfdTunnelApiToken {
    /// Namespace is optional, defaults to the same namespace as the CfdTunnel.
    #[serde(rename = "secretRef")]
    pub secret_ref: CfdTunnelRef,
    /// The key within the secret that holds the token.
    /// Defaults to "CF_API_TOKEN".
    #[serde(default = "default_tunnel_secret_key")]
    pub key: String,
}

fn default_tunnel_secret_key() -> String {
    "CF_API_TOKEN".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum CfdTunnelDns {
    #[serde(rename = "externalDNS")]
    ExternalDNS {
        kind: CfdTunnelExternalDnsKind,
        /// Namespace for the created DNSEndpoint.
        /// Optional. Defaults to the operator's namespace.
        namespace: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum CfdTunnelExternalDnsKind {
    /// For each given dns_name, creates a CNAME record pointing at the tunnel
    #[serde(rename = "generated")]
    Generated {
        endpoints: Vec<CfdTunnelExternalDnsGenerated>,
    },
    /// Gives you full control. Useful to, e.g., use a LoadBalancer IP
    /// if Cloudflare Tunnels is down
    #[serde(rename = "raw")]
    Raw { spec: DNSEndpointSpec },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CfdTunnelExternalDnsGenerated {
    #[serde(rename = "dnsName")]
    dns_name: String,
    #[serde(rename = "setIdentifier")]
    set_identifier: Option<String>,
    #[serde(rename = "recordTTL")]
    record_ttl: Option<i64>,
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "providerSpecific")]
    provider_specific: Option<Vec<ExternalDNSProviderSpecificProperty>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CfdTunnelPodOverrides {
    pub volumes: Option<Vec<Volume>>,
    #[serde(rename = "dnsPolicy")]
    pub dns_policy: Option<String>,
    #[serde(rename = "dnsConfig")]
    pub dns_config: Option<PodDNSConfig>,
    #[serde(rename = "hostUsers")]
    pub host_users: Option<bool>,
    #[serde(rename = "hostNetwork")]
    pub host_network: Option<bool>,
    #[serde(rename = "hostAliases")]
    pub host_aliases: Option<Vec<HostAlias>>,
    pub tolerations: Option<Vec<Toleration>>,
    #[serde(rename = "initContainers")]
    pub init_containers: Option<Vec<Container>>,
    #[serde(rename = "priorityClassName")]
    pub priority_class_name: Option<String>,
    #[serde(rename = "imagePullSecrets")]
    pub image_pull_secrets: Option<Vec<LocalObjectReference>>,
    #[serde(rename = "shareProcessNamespace")]
    pub share_process_namespace: Option<bool>,
}

impl From<CfdTunnelPodOverrides> for PodSpec {
    fn from(value: CfdTunnelPodOverrides) -> Self {
        PodSpec {
            volumes: value.volumes,
            dns_policy: value.dns_policy,
            dns_config: value.dns_config,
            host_users: value.host_users,
            host_network: value.host_network,
            host_aliases: value.host_aliases,
            tolerations: value.tolerations,
            init_containers: value.init_containers,
            priority_class_name: value.priority_class_name,
            image_pull_secrets: value.image_pull_secrets,
            share_process_namespace: value.share_process_namespace,
            ..Default::default()
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct CfdTunnelCredentialsFile {
    #[serde(rename = "AccountTag")]
    account_tag: String,
    #[serde(rename = "TunnelID")]
    tunnel_id: String,
    #[serde(rename = "TunnelSecret")]
    #[serde_as(as = "Base64")]
    tunnel_secret: Vec<u8>,
    #[serde(rename = "Endpoint")]
    endpoint: String,
}

pub struct Context {
    pub name: String,
    pub namespace: String,
    pub watch_namespace: WatchNamespace,
    pub k8s_client: kube::Client,
    pub crd_watch_api: Api<CfdTunnel>,
    pub endpointslice_watch_api: Api<EndpointSlice>,
}

impl Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .field("watch_namespace", &self.watch_namespace)
            .finish()
    }
}

pub fn map_endpointslice_to_crd_ref(
    crd_reader: &reflector::Store<CfdTunnel>,
    endpointslice: &PartialObjectMeta<EndpointSlice>,
) -> Option<reflector::ObjectRef<CfdTunnel>> {
    endpointslice
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get("kubernetes.io/service-name"))
        .and_then(|service| {
            crd_reader.find(|tunnel| {
                let service_ns = tunnel
                    .spec
                    .service_ref
                    .namespace
                    .as_ref()
                    .or(tunnel.meta().namespace.as_ref());
                service_ns == endpointslice.namespace().as_ref()
                    && &tunnel.spec.service_ref.name == service
            })
        })
        .map(|tunnel| reflector::ObjectRef::from_obj(tunnel.as_ref()))
}

#[instrument(level = "trace")]
pub async fn run_once(
    tunnel: Arc<CfdTunnel>,
    ctx: Arc<Context>,
) -> Result<Action, finalizer::Error<Error>> {
    let crd_api: Api<CfdTunnel> = Api::namespaced(
        ctx.k8s_client.clone(),
        &tunnel.namespace().expect("namespaced"),
    );

    finalizer(
        &crd_api,
        "cfdtunnels.cfd-operator.vrtx.sh/cleanup",
        tunnel,
        |event| async {
            match event {
                finalizer::Event::Apply(tunnel) => reconcile(tunnel, ctx).await,
                finalizer::Event::Cleanup(tunnel) => cleanup(tunnel, ctx).await,
            }
        },
    )
    .await
}

#[instrument(level = "trace")]
pub async fn reconcile(mut tunnel: Arc<CfdTunnel>, ctx: Arc<Context>) -> Result<Action> {
    let crd_api: Api<CfdTunnel> = Api::namespaced(
        ctx.k8s_client.clone(),
        &tunnel.namespace().expect("namespaced"),
    );
    let secret_api: Api<Secret> = Api::namespaced(ctx.k8s_client.clone(), &ctx.namespace);
    let configmap_api: Api<ConfigMap> = Api::namespaced(ctx.k8s_client.clone(), &ctx.namespace);
    let deployment_api: Api<Deployment> = Api::namespaced(ctx.k8s_client.clone(), &ctx.namespace);
    let pp = PatchParams::apply(&ctx.name);

    if tunnel
        .status
        .as_ref()
        .and_then(|status| status.tunnel_id.as_ref())
        .is_none()
    {
        let cf_client = cf_client_for_tunnel(&ctx, &tunnel).await?;
        let tunnel_name = format!(
            "{}:{}/{}",
            ctx.name,
            tunnel.name_any(),
            tunnel.namespace().expect("namespaced"),
        );

        let mut credentials = CfdTunnelCredentialsFile {
            account_tag: tunnel.spec.account_id.clone(),
            tunnel_id: "".into(),
            tunnel_secret: vec![0; 32],
            endpoint: "".into(),
        };
        rand::fill(credentials.tunnel_secret.as_mut_slice());

        let credentials_secret = generate_owned_credentials_secret(&ctx, &tunnel, &credentials);
        trace!(
            secret_name = credentials_secret.name_any(),
            "generate secret: {credentials_secret:#?}"
        );
        debug!(
            secret_name = credentials_secret.name_any(),
            "patch secret with new tunnel secret"
        );
        secret_api
            .patch(
                &credentials_secret.name_any(),
                &pp,
                &Patch::Apply(credentials_secret),
            )
            .await
            .map_err(Error::Patch)?;

        let cfd_tunnel = {
            let existing_tunnel = {
                let list_tunnels = list_tunnels::ListTunnels {
                    account_identifier: &tunnel.spec.account_id,
                    params: list_tunnels::Params {
                        name: Some(tunnel_name.clone()),
                        ..Default::default()
                    },
                };
                let result = cf_client
                    .request(&list_tunnels)
                    .await
                    .map_err(Error::CfTunnel)?;
                match result.result.first() {
                    None => None,
                    Some(cfd_tunnel) => {
                        debug!(
                            cf_tunnel = ?cfd_tunnel,
                            "found existing tunnel, updating tunnel secret"
                        );

                        let update_tunnel = update_tunnel::UpdateTunnel {
                            account_identifier: &tunnel.spec.account_id,
                            tunnel_id: &cfd_tunnel.id.to_string(),
                            params: update_tunnel::Params {
                                name: &tunnel_name,
                                tunnel_secret: &credentials.tunnel_secret,
                                metadata: None,
                            },
                        };
                        cf_client
                            .request(&update_tunnel)
                            .await
                            .map_err(Error::CfTunnel)?;

                        Some(cfd_tunnel.clone())
                    }
                }
            };

            match existing_tunnel {
                None => {
                    let new_tunnel = {
                        let create_tunnel = create_tunnel::CreateTunnel {
                            account_identifier: &tunnel.spec.account_id,
                            params: create_tunnel::Params {
                                tunnel_secret: &credentials.tunnel_secret,
                                name: &tunnel_name,
                                config_src: &cfd_tunnel::ConfigurationSrc::Local,
                                metadata: None,
                            },
                        };

                        cf_client
                            .request(&create_tunnel)
                            .await
                            .map_err(Error::CfTunnel)?
                    };

                    debug!(
                        cf_tunnel = ?new_tunnel.result,
                        "new tunnel created"
                    );

                    new_tunnel.result
                }
                Some(cfd_tunnel) => cfd_tunnel,
            }
        };

        credentials.tunnel_id = cfd_tunnel.id.into();
        let credentials_secret = generate_owned_credentials_secret(&ctx, &tunnel, &credentials);
        trace!(
            secret_name = credentials_secret.name_any(),
            "generate secret: {credentials_secret:#?}"
        );
        debug!(
            secret_name = credentials_secret.name_any(),
            "patch secret with tunnel id"
        );
        secret_api
            .patch(
                &credentials_secret.name_any(),
                &pp,
                &Patch::Apply(credentials_secret.clone()),
            )
            .await
            .map_err(Error::Patch)?;
        cleanup_old_resources(&ctx, &tunnel, &ctx.namespace, &[&credentials_secret]).await?;

        let patch = Patch::Merge(json!({
            "status": CfdTunnelStatus {
                tunnel_id: Some(cfd_tunnel.id.into()),
                conditions: vec![Condition {
                    status: "True".into(),
                    type_: "Ready".into(),
                    reason: "CfTunnelConfigured".into(),
                    message: "".into(),
                    observed_generation: tunnel.metadata.generation,
                    last_transition_time: k8s_openapi::jiff::Timestamp::now().into(),
                }],
                ..tunnel.status.as_ref().cloned().unwrap_or_default()
            }
        }));
        debug!("patch status with tunnel id");

        tunnel = Arc::new(
            crd_api
                .patch_status(&tunnel.name_any(), &pp, &patch)
                .await
                .map_err(Error::Patch)?,
        );
    }

    let tunnel_id = tunnel
        .status
        .as_ref()
        .and_then(|status| status.tunnel_id.as_ref())
        .expect("tunnel_id");
    let configmap = generate_owned_configmap(&ctx, &tunnel, tunnel_id);
    configmap_api
        .patch(&configmap.name_any(), &pp, &Patch::Apply(configmap.clone()))
        .await
        .map_err(Error::Patch)?;

    let endpointslices = ctx
        .endpointslice_watch_api
        .list(
            &ListParams::default()
                .labels(&format!(
                    "kubernetes.io/service-name={}",
                    &tunnel.spec.service_ref.name
                ))
                .fields(&format!(
                    "metadata.namespace={}",
                    tunnel
                        .spec
                        .service_ref
                        .namespace
                        .as_ref()
                        .or(tunnel.meta().namespace.as_ref())
                        .expect("namespaced")
                )),
        )
        .await
        .map_err(Error::List)?;
    trace!(endpointslices = ?endpointslices, "found endpoint slices");

    let mut node_names: Vec<_> = endpointslices
        .iter()
        .flat_map(|slice| {
            slice
                .endpoints
                .iter()
                .filter(|endpoint| {
                    endpoint
                        .conditions
                        .as_ref()
                        .and_then(|conditions| conditions.serving.or(Some(true)))
                        .unwrap_or_default()
                })
                .map(|endpoint| endpoint.node_name.clone())
        })
        .flatten()
        .collect();
    node_names.sort();
    node_names.dedup();
    debug!(node_names = ?node_names, "resolved nodes");

    let metrics_sock_addr: SocketAddr = tunnel
        .spec
        .metrics_addr
        .parse()
        .map_err(anyhow::Error::from)?;

    let deployment = generate_owned_deployment(
        &ctx,
        &tunnel,
        tunnel_id,
        &node_names,
        &configmap.name_any(),
        &base_resource_name(&tunnel),
        &metrics_sock_addr,
    );
    trace!(
        deployment_name = deployment.name_any(),
        "generate deployment: {deployment:#?}"
    );
    debug!(deployment_name = deployment.name_any(), "patch deployment");
    deployment_api
        .patch(
            &deployment.name_any(),
            &pp,
            &Patch::Apply(deployment.clone()),
        )
        .await
        .map_err(Error::Patch)?;

    if let Some(dns) = tunnel.spec.dns.as_ref() {
        let dns_endpoint_api = external_dns_api(&ctx, &ctx.namespace);
        let dns_endpoint = generated_owned_dnsendpoint(&ctx, &tunnel, tunnel_id, dns);
        trace!(
            dns_endpoint_name = dns_endpoint.name_any(),
            "generate dnsendpoint: {dns_endpoint:#?}"
        );

        debug!(
            dns_endpoint_name = dns_endpoint.name_any(),
            "patch dnsendpoint"
        );
        dns_endpoint_api
            .patch(
                &dns_endpoint.name_any(),
                &pp,
                &Patch::Apply(dns_endpoint.clone()),
            )
            .await
            .map_err(Error::Patch)?;

        if let Some(old_namespace) = tunnel
            .status
            .as_ref()
            .and_then(|status| status.dns_endpoint_namespace.as_ref())
            && old_namespace != dns_endpoint.namespace().as_ref().expect("namespaced")
        {
            cleanup_old_resources::<DNSEndpoint>(&ctx, &tunnel, old_namespace, &[]).await?;
        }

        let patch = Patch::Merge(json!({
            "status": CfdTunnelStatus {
                dns_endpoint_namespace: dns_endpoint.namespace(),
                ..tunnel.status.as_ref().cloned().unwrap_or_default()
            }
        }));
        debug!("patch status with dns_endpoint_namespace");

        tunnel = Arc::new(
            crd_api
                .patch_status(&tunnel.name_any(), &pp, &patch)
                .await
                .map_err(Error::Patch)?,
        );

        cleanup_old_resources(
            &ctx,
            &tunnel,
            &dns_endpoint.namespace().expect("namespaced"),
            &[&dns_endpoint],
        )
        .await?;
    } else {
        if let Some(namespace) = tunnel
            .status
            .as_ref()
            .and_then(|status| status.dns_endpoint_namespace.as_ref())
        {
            match cleanup_old_resources::<DNSEndpoint>(&ctx, &tunnel, namespace, &[]).await {
                Ok(()) => {}
                // The CRD doesn't exist
                Err(Error::Delete(kube::Error::Api(status))) if status.is_not_found() => {}
                Err(err) => return Err(err),
            }

            let patch = Patch::Merge(json!({
                "status": CfdTunnelStatus {
                    dns_endpoint_namespace: None,
                    ..tunnel.status.as_ref().cloned().unwrap_or_default()
                }
            }));
            debug!("patch status with no dns_endpoint_namespace");

            tunnel = Arc::new(
                crd_api
                    .patch_status(&tunnel.name_any(), &pp, &patch)
                    .await
                    .map_err(Error::Patch)?,
            );
        }
    }

    cleanup_old_resources(&ctx, &tunnel, &ctx.namespace, &[&configmap]).await?;
    cleanup_old_resources(&ctx, &tunnel, &ctx.namespace, &[&deployment]).await?;

    Ok(Action::requeue(Duration::from_secs(3600)))
}

#[instrument(level = "trace")]
pub async fn cleanup(tunnel: Arc<CfdTunnel>, ctx: Arc<Context>) -> Result<Action> {
    match tunnel.status.as_ref() {
        Some(CfdTunnelStatus {
            tunnel_id: Some(tunnel_id),
            conditions: _,
            dns_endpoint_namespace: _,
        }) => {
            cleanup_old_resources::<Deployment>(&ctx, &tunnel, &ctx.namespace, &[]).await?;

            let cf_client = cf_client_for_tunnel(&ctx, &tunnel).await?;
            let delete_tunnel_request = delete_tunnel::DeleteTunnel {
                account_identifier: &tunnel.spec.account_id,
                tunnel_id,
                params: Default::default(),
            };
            debug!(cf_tunnel_id = tunnel_id, "delete tunnel");
            cf_client
                .request(&delete_tunnel_request)
                .await
                .map_err(Error::CfTunnel)?;

            Ok(Action::await_change())
        }
        _ => Ok(Action::await_change()),
    }
}

pub fn error_policy(
    tunnel: Arc<CfdTunnel>,
    error: &finalizer::Error<Error>,
    _ctx: Arc<Context>,
) -> Action {
    error!(
        tunnel = ?tunnel,
        error = error.to_string(),
        "failed to reconcile tunnel"
    );
    Action::requeue(Duration::from_secs(30))
}

fn generate_owned_credentials_secret(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    credentials: &CfdTunnelCredentialsFile,
) -> Secret {
    let owner_ref = tunnel.controller_owner_ref(&()).expect("owner_ref");
    let credentials = serde_json::to_string(credentials).expect("credentials");
    let common_labels = common_labels(ctx, tunnel);

    Secret {
        metadata: ObjectMeta {
            name: Some(base_resource_name(tunnel)),
            namespace: Some(ctx.namespace.clone()),
            owner_references: Some(vec![owner_ref]),
            labels: Some(common_labels),
            ..Default::default()
        },
        type_: Some("Opaque".into()),
        string_data: Some([("credentials.json".into(), credentials)].into()),
        ..Default::default()
    }
}

fn indent_n(string: &str, count: usize) -> String {
    let indentation: String = iter::repeat_n(" ", count).collect();
    string
        .split("\n")
        .map(|line| format!("{indentation}{line}\n"))
        .collect()
}

fn resource_name(tunnel: &Arc<CfdTunnel>, hash: u64) -> String {
    format!("{}-{hash:x}", base_resource_name(tunnel))
}

fn base_resource_name(tunnel: &Arc<CfdTunnel>) -> String {
    format!(
        "cfd-{}-{}",
        tunnel.namespace().expect("namespaced"),
        tunnel.name_any(),
    )
}

fn generate_owned_configmap(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    tunnel_id: &str,
) -> ConfigMap {
    let owner_ref = tunnel.controller_owner_ref(&()).expect("owner_ref");
    let common_labels = common_labels(ctx, tunnel);
    let ingress_configs = tunnel
        .spec
        .ingress
        .iter()
        .map(|ingress_rule| {
            [
                Some(format!("- service: {}", ingress_rule.service)),
                ingress_rule
                    .hostname
                    .as_ref()
                    .map(|hostname| indent_n(&format!("hostname: {hostname}"), 2)),
                ingress_rule
                    .path
                    .as_ref()
                    .map(|path| indent_n(&format!("path: {path}"), 2)),
                ingress_rule
                    .origin_request_config
                    .as_ref()
                    .map(|config| indent_n(&format!("originRequest:\n{}", indent_n(config, 2)), 2)),
            ]
            .into_iter()
            .flatten()
            .map(|line| format!("{line}\n"))
            .collect::<String>()
        })
        .collect::<String>();

    let origin_request = tunnel
        .spec
        .origin_request_config
        .as_ref()
        .map(|config| format!("\noriginRequest:\n{}", indent_n(config, 2)))
        .unwrap_or_default();

    let config = format!(
        "tunnel: {}
credentials-file: /etc/cloudflared/credentials/credentials.json
ingress:
{}{}",
        tunnel_id,
        indent_n(&ingress_configs, 2),
        origin_request
    );
    let mut hasher = DefaultHasher::new();
    config.hash(&mut hasher);
    let hash = hasher.finish();

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(resource_name(tunnel, hash)),
            namespace: Some(ctx.namespace.clone()),
            labels: Some(common_labels),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        data: Some([("config.yaml".into(), config)].into()),
        ..Default::default()
    }
}

fn generate_owned_deployment(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    tunnel_id: &str,
    node_names: &[String],
    configmap_name: &str,
    secret_name: &str,
    metrics_socket_addr: &SocketAddr,
) -> Deployment {
    let owner_ref = tunnel.controller_owner_ref(&()).expect("owner_ref");
    let common_labels = common_labels(ctx, tunnel);
    let mut labels: BTreeMap<String, String> = [
        ("app.kubernetes.io/name".into(), "cloudflared".into()),
        (
            "app.kubernetes.io/instance".into(),
            base_resource_name(tunnel),
        ),
    ]
    .into();
    labels.extend(common_labels);

    let mut cloudflared_container = Container {
        name: "cloudflared".into(),
        image: Some("docker.io/cloudflare/cloudflared:latest".into()),
        image_pull_policy: Some("Always".into()),
        env: Some(vec![
            EnvVar {
                name: "CF_TUNNEL_ID".into(),
                value: Some(tunnel_id.into()),
                ..Default::default()
            },
            EnvVar {
                name: "GOMEMLIMIT".into(),
                value_from: Some(EnvVarSource {
                    resource_field_ref: Some(ResourceFieldSelector {
                        resource: "limits.memory".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        args: Some(vec![
            "tunnel".into(),
            "--no-autoupdate".into(),
            "--loglevel".into(),
            tunnel.spec.log_level.clone(),
            "--protocol".into(),
            tunnel.spec.protocol.clone(),
            "--metrics".into(),
            tunnel.spec.metrics_addr.clone(),
            "run".into(),
        ]),
        liveness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                // cloudflared serves a /ready endpoint which returns 200 if and only if
                // it has an active connection to Cloudflare's network.
                path: Some("/ready".into()),
                port: IntOrString::Int(metrics_socket_addr.port().into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "config".into(),
                mount_path: "/etc/cloudflared".into(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "credentials".into(),
                mount_path: "/etc/cloudflared/credentials".into(),
                read_only: Some(true),
                ..Default::default()
            },
        ]),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".into()]),
                ..Default::default()
            }),
            privileged: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    };

    if let Some(overrides) = &tunnel.spec.container_overrides {
        cloudflared_container.merge_from(overrides.clone());
    }

    let mut pod_spec = PodSpec {
        affinity: Some(Affinity {
            node_affinity: match node_names.len() {
                0 => None,
                _ => Some(NodeAffinity {
                    required_during_scheduling_ignored_during_execution: Some(NodeSelector {
                        node_selector_terms: vec![NodeSelectorTerm {
                            match_expressions: Some(vec![NodeSelectorRequirement {
                                key: "kubernetes.io/hostname".into(),
                                operator: "In".into(),
                                values: Some(node_names.into()),
                            }]),
                            ..Default::default()
                        }],
                    }),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        topology_spread_constraints: Some(vec![TopologySpreadConstraint {
            max_skew: 1,
            when_unsatisfiable: "DoNotSchedule".to_string(),
            topology_key: "kubernetes.io/hostname".to_string(),
            label_selector: Some(LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            }),
            match_label_keys: Some(vec!["pod-template-hash".into()]),
            ..Default::default()
        }]),
        security_context: Some(PodSecurityContext {
            run_as_user: Some(1000),
            run_as_group: Some(1000),
            run_as_non_root: Some(true),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        volumes: Some(vec![
            Volume {
                name: "config".into(),
                config_map: Some(ConfigMapVolumeSource {
                    name: configmap_name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Volume {
                name: "credentials".into(),
                secret: Some(SecretVolumeSource {
                    secret_name: Some(secret_name.into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };

    if let Some(overrides) = &tunnel.spec.pod_spec_overrides {
        pod_spec.merge_from(overrides.clone().into());
    }

    let additional_containers = tunnel
        .spec
        .additional_containers
        .as_ref()
        .cloned()
        .unwrap_or_default();
    pod_spec.containers = vec![cloudflared_container];
    pod_spec.containers.extend(additional_containers);

    Deployment {
        metadata: ObjectMeta {
            name: Some(base_resource_name(tunnel)),
            namespace: Some(ctx.namespace.clone()),
            owner_references: Some(vec![owner_ref]),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(node_names.len() as i32),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(pod_spec),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn generated_owned_dnsendpoint(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    tunnel_id: &str,
    dns: &CfdTunnelDns,
) -> DNSEndpoint {
    let owner_ref = tunnel.controller_owner_ref(&()).expect("owner_ref");
    let metadata = ObjectMeta {
        name: Some(base_resource_name(tunnel)),
        namespace: Some(ctx.namespace.clone()),
        owner_references: Some(vec![owner_ref]),
        labels: Some(common_labels(ctx, tunnel)),
        ..Default::default()
    };
    match dns {
        CfdTunnelDns::ExternalDNS { kind, namespace } => match kind {
            CfdTunnelExternalDnsKind::Raw { spec } => DNSEndpoint {
                metadata: ObjectMeta {
                    namespace: namespace.as_ref().cloned().or(metadata.namespace),
                    ..metadata
                },
                spec: spec.clone(),
            },
            CfdTunnelExternalDnsKind::Generated { endpoints } => DNSEndpoint {
                metadata: ObjectMeta {
                    namespace: namespace.as_ref().cloned().or(metadata.namespace),
                    ..metadata
                },
                spec: DNSEndpointSpec {
                    endpoints: endpoints
                        .iter()
                        .cloned()
                        .map(|endpoint| ExternalDNSEndpoint {
                            dns_name: endpoint.dns_name,
                            record_type: "CNAME".to_string(),
                            targets: vec![format!("{}.cfargotunnel.com", tunnel_id)],
                            record_ttl: endpoint.record_ttl.unwrap_or_default(),
                            labels: endpoint.labels.unwrap_or_default(),
                            set_identifier: endpoint.set_identifier.unwrap_or_default(),
                            provider_specific: endpoint.provider_specific.unwrap_or_default(),
                        })
                        .collect(),
                },
            },
        },
    }
}

async fn cleanup_old_resources<K>(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    namespace: &str,
    current_resources: &[&K],
) -> Result<()>
where
    K: Clone + DeserializeOwned + Debug,
    K: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope>,
    <K as kube::Resource>::DynamicType: std::default::Default,
{
    let api: Api<K> = Api::namespaced(ctx.k8s_client.clone(), namespace);
    let common_labels = common_labels(ctx, tunnel);
    let result = api
        .delete_collection(
            &DeleteParams::default(),
            &ListParams::default()
                .fields(
                    &current_resources
                        .iter()
                        .map(|r| format!("metadata.name!={}", r.name_any()))
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .labels_from(&Selector::from_iter(common_labels)),
        )
        .await
        .map_err(Error::Delete)?;

    debug!(result = ?result, "delete old resources");

    Ok(())
}

async fn cf_client_for_tunnel(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
) -> Result<cloudflare::framework::client::async_api::Client> {
    let api_token_secret_api: Api<Secret> = Api::namespaced(
        ctx.k8s_client.clone(),
        tunnel
            .spec
            .api_token
            .secret_ref
            .namespace
            .as_ref()
            .unwrap_or(tunnel.namespace().as_ref().expect("namespaced")),
    );
    let api_token_secret = api_token_secret_api
        .get(&tunnel.spec.api_token.secret_ref.name)
        .await
        .map_err(Error::ResourceNotFound)?;
    let api_token = String::from_utf8(
        api_token_secret
            .data
            .as_ref()
            .and_then(|data| data.get(&tunnel.spec.api_token.key))
            .ok_or(Error::NotFound(format!(
                "key {} not found in secret {}",
                &tunnel.spec.api_token.key, &tunnel.spec.api_token.secret_ref.name
            )))?
            .0
            .clone(),
    )
    .map_err(anyhow::Error::from)?;

    cloudflare::framework::client::async_api::Client::new(
        cloudflare::framework::auth::Credentials::UserAuthToken {
            token: api_token.clone(),
        },
        Default::default(),
        cloudflare::framework::Environment::Production,
    )
    .map_err(Error::CfError)
}

fn common_labels(ctx: &Arc<Context>, tunnel: &Arc<CfdTunnel>) -> BTreeMap<String, String> {
    [
        (
            "cfd-operator.vrtx.sh/resource".into(),
            format!(
                "cfdtunnel-{}-{}",
                tunnel.namespace().as_ref().expect("namespaced"),
                tunnel.name_any()
            ),
        ),
        ("app.kubernetes.io/managed-by".into(), ctx.name.clone()),
    ]
    .into()
}

// https://github.com/kubernetes-sigs/external-dns/blob/master/config/crd/standard/dnsendpoints.externaldns.k8s.io.yaml
#[derive(CustomResource, Clone, PartialEq, Serialize, Deserialize, Debug, JsonSchema, Default)]
#[kube(
    kind = "DNSEndpoint",
    group = "externaldns.k8s.io",
    version = "v1alpha1",
    derive = "PartialEq",
    namespaced
)]
pub struct DNSEndpointSpec {
    pub endpoints: Vec<ExternalDNSEndpoint>,
}

// https://github.com/kubernetes-sigs/external-dns/blob/master/endpoint/endpoint.go
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, JsonSchema, Default)]
pub struct ExternalDNSEndpoint {
    #[serde(rename = "dnsName")]
    pub dns_name: String,
    pub targets: Vec<String>,
    #[serde(rename = "recordType")]
    pub record_type: String,
    #[serde(rename = "setIdentifier")]
    pub set_identifier: String,
    #[serde(rename = "recordTTL")]
    pub record_ttl: i64,
    pub labels: BTreeMap<String, String>,
    #[serde(rename = "providerSpecific")]
    pub provider_specific: Vec<ExternalDNSProviderSpecificProperty>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, JsonSchema, Default)]
pub struct ExternalDNSProviderSpecificProperty {
    pub name: String,
    pub value: String,
}

fn external_dns_api(ctx: &Arc<Context>, namespace: &str) -> Api<DNSEndpoint> {
    Api::namespaced(ctx.k8s_client.clone(), namespace)
}
