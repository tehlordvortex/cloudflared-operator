use std::{
    collections::BTreeMap,
    fmt::Debug,
    hash::{DefaultHasher, Hash, Hasher},
    iter,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::ext_cr::{
    dnsendpoint::v1alpha1::{DNSEndpoint, DnsEndpointEndpoints, DnsEndpointSpec},
    servicemonitor::v1::{
        ServiceMonitor, ServiceMonitorEndpoints, ServiceMonitorNamespaceSelector,
        ServiceMonitorSelector, ServiceMonitorSpec,
    },
};
use cloudflare::endpoints::cfd_tunnel::{
    self, create_tunnel, delete_tunnel, list_tunnels, update_tunnel,
};
use futures::FutureExt;
use k8s_openapi::{
    DeepMerge,
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{
            Affinity, Capabilities, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort,
            EnvVar, EnvVarSource, HTTPGetAction, HostAlias, LocalObjectReference, NodeAffinity,
            NodeSelector, NodeSelectorRequirement, NodeSelectorTerm, PodDNSConfig,
            PodSecurityContext, PodSpec, PodTemplateSpec, Probe, ResourceFieldSelector,
            SeccompProfile, Secret, SecretVolumeSource, SecurityContext, Service, ServicePort,
            ServiceSpec, Sysctl, Toleration, TopologySpreadConstraint, Volume, VolumeMount,
        },
        discovery::v1::EndpointSlice,
    },
    apimachinery::pkg::{
        apis::meta::v1::{Condition, LabelSelector, OwnerReference},
        util::intstr::IntOrString,
    },
};
use kube::{
    Api, CustomResource, KubeSchema, Resource, ResourceExt,
    api::{DeleteParams, ListParams, ObjectMeta, PartialObjectMeta, Patch, PatchParams},
    core::{Selector, cel::MergeStrategy},
    runtime::{controller::Action, finalizer, reflector},
};
use metrics::{counter, histogram};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use serde_with::{base64::Base64, serde_as};
use tracing::{debug, instrument, trace, warn};

use crate::{Error, Result};

/// Manages a cloudflared tunnel and its replicas for a particular service
#[allow(clippy::duplicated_attributes)]
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
#[kube(printcolumn(
    name = "Service",
    type_ = "string",
    json_path = ".spec.serviceRef.name",
    description = "Service used to identify nodes serving traffic for this instance"
))]
#[kube(printcolumn(
    name = "TunnelId",
    type_ = "string",
    json_path = ".status.tunnelId",
    description = "Cloudflare Tunnel ID"
))]
pub struct CfdTunnelSpec {
    /// The Account ID under which the tunnel will be created (with the format
    /// {operator_name}:{cr_namespace}/{cr_name}).
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
    /// Ingress rules that configure how traffic gets routed once it hits
    /// cloudflared. The hostnames here are not automatically configured as
    /// DNS records.
    pub ingress: Vec<CfdTunnelIngressRule>,
    /// Customize the request sent by cloudflared to your origin.
    /// May be overriden per-ingress.
    /// Accepts a YAML string of the fields as described in the documentation:
    /// https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/
    #[serde(
        rename = "originRequestConfig",
        skip_serializing_if = "Option::is_none"
    )]
    pub origin_request_config: Option<String>,
    /// Override some fields in the pod definition.
    /// This is merged into the generated definition and takes higher priority.
    /// See also "container_overrides" and "additional_containers".
    #[serde(rename = "podSpecOverrides", skip_serializing_if = "Option::is_none")]
    pub pod_spec_overrides: Option<CfdTunnelPodOverrides>,
    /// Override fields in the cloudflared container definition.
    /// This is merged into the generated definition and takes higher priority.
    #[serde(rename = "containerOverrides", skip_serializing_if = "Option::is_none")]
    pub container_overrides: Option<Container>,
    /// Add additional containers to the pod
    #[serde(
        rename = "additionalContainers",
        skip_serializing_if = "Option::is_none"
    )]
    pub additional_containers: Option<Vec<Container>>,
    /// If present, enables DNS configuration with External DNS.
    /// This supports the dnsendpoints.externaldns.k8s.io/v1alpha1 CRD, which must
    /// be present in the cluster.
    /// See https://kubernetes-sigs.github.io/external-dns/latest/docs/sources/crd
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<CfdTunnelDns>,
    /// If present, creates a ServiceMonitor, and corresponding Service,
    /// to monitor the Deployment. The Prometheus Operator must be present
    /// in the cluster.
    #[serde(rename = "serviceMonitor", skip_serializing_if = "Option::is_none")]
    pub servicemonitor: Option<CfdServiceMonitor>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, KubeSchema, Default)]
pub struct CfdTunnelStatus {
    /// Cloudflare Tunnel ID
    #[serde(rename = "tunnelId")]
    pub tunnel_id: Option<String>,
    /// Contains only one condition, Ready, which is set to True
    /// once the tunnel has been configured on Cloudflare
    #[x_kube(merge_strategy = MergeStrategy::ListType(ListMerge::Map(vec!["type".into()])))]
    pub conditions: Option<Vec<Condition>>,
    #[serde(rename = "dnsEndpointNamespace")]
    pub dnsendpoint_namespace: Option<String>,
    #[serde(rename = "serviceMonitorNamespace")]
    pub servicemonitor_namespace: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(
        rename = "originRequestConfig",
        skip_serializing_if = "Option::is_none"
    )]
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
pub struct CfdTunnelPodOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<Volume>>,
    #[serde(rename = "dnsPolicy", skip_serializing_if = "Option::is_none")]
    pub dns_policy: Option<String>,
    #[serde(rename = "dnsConfig", skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<PodDNSConfig>,
    #[serde(rename = "hostUsers", skip_serializing_if = "Option::is_none")]
    pub host_users: Option<bool>,
    #[serde(rename = "hostNetwork", skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,
    #[serde(rename = "hostAliases", skip_serializing_if = "Option::is_none")]
    pub host_aliases: Option<Vec<HostAlias>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tolerations: Option<Vec<Toleration>>,
    #[serde(rename = "initContainers", skip_serializing_if = "Option::is_none")]
    pub init_containers: Option<Vec<Container>>,
    #[serde(rename = "priorityClassName", skip_serializing_if = "Option::is_none")]
    pub priority_class_name: Option<String>,
    #[serde(rename = "imagePullSecrets", skip_serializing_if = "Option::is_none")]
    pub image_pull_secrets: Option<Vec<LocalObjectReference>>,
    #[serde(
        rename = "shareProcessNamespace",
        skip_serializing_if = "Option::is_none"
    )]
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
    Raw { spec: DnsEndpointSpec },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CfdTunnelExternalDnsGenerated {
    #[serde(rename = "dnsName")]
    dns_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// "dnsName", "recordType", and "targets" are ignored
    config: Option<DnsEndpointEndpoints>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CfdServiceMonitor {
    /// The namespace to create the service monitor in, defaults to the same namespace
    /// as the operator. The corresponding metrics Service is always created in the
    /// namespace of the operator, since that's where the Deployment lives.
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    /// "selector", "namespaceSelector" and "endpoints" are ignored
    config: Option<ServiceMonitorSpec>,
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
    pub dry_run: bool,
    pub k8s_client: kube::Client,
}

impl Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .field("dry_run", &self.dry_run)
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

#[instrument(skip(tunnel))]
pub async fn run_once(
    tunnel: Arc<CfdTunnel>,
    ctx: Arc<Context>,
) -> Result<Action, finalizer::Error<Error>> {
    let start = Instant::now();
    let crd_api: Api<CfdTunnel> = Api::namespaced(
        ctx.k8s_client.clone(),
        &tunnel.namespace().expect("namespaced"),
    );
    trace!("reconcile once with resource state: {tunnel:#?}");

    finalizer(
        &crd_api,
        "cfdtunnels.cfd-operator.vrtx.sh/cleanup",
        tunnel.clone(),
        {
            let ctx = ctx.clone();
            |event| async move {
                match event {
                    finalizer::Event::Apply(tunnel) => reconcile(tunnel, ctx).await,
                    finalizer::Event::Cleanup(tunnel) => cleanup(tunnel, ctx).await,
                }
            }
        },
    )
    .then(async |result| {
        let duration = start.elapsed().as_millis() as f64 / 1000.0;
        let metrics_labels = metrics_labels(&ctx, &tunnel);

        counter!(
            "cfdtunnel_controller_reconciliations_total",
            &metrics_labels,
        )
        .increment(1);
        histogram!(
            "cfdtunnel_controller_reconciliation_duration_seconds",
            &metrics_labels
        )
        .record(duration);

        result
    })
    .await
}

#[instrument(skip(tunnel, ctx))]
pub async fn reconcile(mut tunnel: Arc<CfdTunnel>, ctx: Arc<Context>) -> Result<Action> {
    let crd_api: Api<CfdTunnel> = Api::namespaced(
        ctx.k8s_client.clone(),
        &tunnel.namespace().expect("namespaced"),
    );
    let secret_api: Api<Secret> = Api::namespaced(ctx.k8s_client.clone(), &ctx.namespace);
    let configmap_api: Api<ConfigMap> = Api::namespaced(ctx.k8s_client.clone(), &ctx.namespace);
    let deployment_api: Api<Deployment> = Api::namespaced(ctx.k8s_client.clone(), &ctx.namespace);
    let endpointslice_api: Api<EndpointSlice> = Api::namespaced(
        ctx.k8s_client.clone(),
        tunnel
            .spec
            .service_ref
            .namespace
            .as_ref()
            .or(tunnel.namespace().as_ref())
            .expect("namespaced"),
    );
    let pp = PatchParams::apply(&ctx.name);

    let result = {
        let mut recreate_deployment = false;

        if tunnel
            .status
            .as_ref()
            .and_then(|status| status.tunnel_id.as_ref())
            .is_none()
        {
            recreate_deployment = true; // cloudflared must restart to pick up the new secret

            let cf_client = cf_client_for_tunnel(&ctx, &tunnel).await?;
            let tunnel_name = format!(
                "{}:{}/{}",
                ctx.name,
                tunnel.namespace().expect("namespaced"),
                tunnel.name_any(),
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

            if !ctx.dry_run {
                secret_api
                    .patch(
                        &credentials_secret.name_any(),
                        &pp,
                        &Patch::Apply(credentials_secret),
                    )
                    .await
                    .map_err(Error::Patch)?;
            }

            let cfd_tunnel_id = {
                let existing_tunnel = {
                    let list_tunnels = list_tunnels::ListTunnels {
                        account_identifier: &tunnel.spec.account_id,
                        params: list_tunnels::Params {
                            name: Some(tunnel_name.clone()),
                            ..Default::default()
                        },
                    };
                    debug!(request = ?list_tunnels, "list tunnels");
                    let result = cf_client
                        .request(&list_tunnels)
                        .await
                        .map_err(Error::CfTunnel)?;

                    match result.result.first() {
                        None => None,
                        Some(cfd_tunnel) => {
                            let update_tunnel = update_tunnel::UpdateTunnel {
                                account_identifier: &tunnel.spec.account_id,
                                tunnel_id: &cfd_tunnel.id.to_string(),
                                params: update_tunnel::Params {
                                    name: &tunnel_name,
                                    tunnel_secret: &credentials.tunnel_secret,
                                    metadata: None,
                                },
                            };
                            debug!(
                                request = ?update_tunnel,
                                "found existing tunnel, updating tunnel secret"
                            );

                            if !ctx.dry_run {
                                cf_client
                                    .request(&update_tunnel)
                                    .await
                                    .map_err(Error::CfTunnel)?;
                            }

                            Some(cfd_tunnel.id.to_string())
                        }
                    }
                };

                match existing_tunnel {
                    None => {
                        let create_tunnel = create_tunnel::CreateTunnel {
                            account_identifier: &tunnel.spec.account_id,
                            params: create_tunnel::Params {
                                tunnel_secret: &credentials.tunnel_secret,
                                name: &tunnel_name,
                                config_src: &cfd_tunnel::ConfigurationSrc::Local,
                                metadata: None,
                            },
                        };
                        debug!(request = ?create_tunnel, "create tunnel");

                        if !ctx.dry_run {
                            let new_tunnel = cf_client
                                .request(&create_tunnel)
                                .await
                                .map_err(Error::CfTunnel)?;

                            new_tunnel.result.id.to_string()
                        } else {
                            "dry_run".into()
                        }
                    }
                    Some(cfd_tunnel) => cfd_tunnel,
                }
            };

            credentials.tunnel_id = cfd_tunnel_id.clone();
            let credentials_secret = generate_owned_credentials_secret(&ctx, &tunnel, &credentials);
            trace!(
                secret_name = credentials_secret.name_any(),
                "generate secret: {credentials_secret:#?}"
            );
            debug!(
                secret_name = credentials_secret.name_any(),
                tunnel_id = credentials.tunnel_id,
                "patch secret with tunnel id"
            );

            if !ctx.dry_run {
                secret_api
                    .patch(
                        &credentials_secret.name_any(),
                        &pp,
                        &Patch::Apply(credentials_secret.clone()),
                    )
                    .await
                    .map_err(Error::Patch)?;
            }

            cleanup_old_resources(&ctx, &tunnel, &ctx.namespace, [&credentials_secret]).await?;

            let new_status = CfdTunnelStatus {
                tunnel_id: Some(cfd_tunnel_id),
                ..tunnel.status.as_ref().cloned().unwrap_or_default()
            };

            let patch = Patch::Apply(json!({
                "apiVersion": CfdTunnel::api_version(&()),
                "kind": CfdTunnel::kind(&()),
                "status": new_status.clone(),
            }));
            debug!(patch = ?patch, "patch status with tunnel id");

            if !ctx.dry_run {
                let pp = PatchParams::apply(&ctx.name).force();
                tunnel = Arc::new(
                    crd_api
                        .patch_status(&tunnel.name_any(), &pp, &patch)
                        .await
                        .map_err(Error::Patch)?,
                );
            }

            let mut new_tunnel = (*tunnel).clone();
            new_tunnel.status = Some(new_status);
            tunnel = Arc::new(new_tunnel);
        }

        let tunnel_id = tunnel
            .status
            .as_ref()
            .and_then(|status| status.tunnel_id.as_ref())
            .expect("tunnel_id")
            .clone();

        let configmap = generate_owned_configmap(&ctx, &tunnel, &tunnel_id);
        trace!(
            configmap_name = configmap.name_any(),
            "generate configmap: {configmap:#?}"
        );
        debug!(configmap_name = configmap.name_any(), "patch configmap");

        if !ctx.dry_run {
            configmap_api
                .patch(&configmap.name_any(), &pp, &Patch::Apply(configmap.clone()))
                .await
                .map_err(Error::Patch)?;
        }

        let endpointslices = endpointslice_api
            .list(&ListParams::default().labels(&format!(
                "kubernetes.io/service-name={}",
                &tunnel.spec.service_ref.name
            )))
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
                            // Only consider endpoints that are not terminating
                            .and_then(|conditions| {
                                conditions.terminating.or(Some(false)).map(|c| !c)
                            })
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
            &tunnel_id,
            &node_names,
            &configmap.name_any(),
            &base_resource_name(&tunnel),
            &metrics_sock_addr,
        );
        trace!(
            deployment_name = deployment.name_any(),
            "generate deployment: {deployment:#?}"
        );
        debug!(
            deployment_name = deployment.name_any(),
            recreate_deployment, "patch deployment"
        );

        if recreate_deployment {
            cleanup_old_resources::<Deployment>(&ctx, &tunnel, &ctx.namespace, &[]).await?;
        }

        if !ctx.dry_run {
            deployment_api
                .patch(
                    &deployment.name_any(),
                    &pp,
                    &Patch::Apply(deployment.clone()),
                )
                .await
                .map_err(Error::Patch)?;
        }

        let dnsendpoint = tunnel.spec.dns.as_ref().map(|dns| {
            let dnsendpoint = generated_owned_dnsendpoint(&ctx, &tunnel, &tunnel_id, dns);
            trace!(
                dnsendpoint_name = dnsendpoint.name_any(),
                "generate dnsendpoint: {dnsendpoint:#?}"
            );

            dnsendpoint
        });

        if let Some(ref dnsendpoint) = dnsendpoint {
            let dnsendpoint_api: Api<DNSEndpoint> = Api::namespaced(
                ctx.k8s_client.clone(),
                dnsendpoint.namespace().as_ref().expect("namespaced"),
            );

            debug!(
                dnsendpoint_name = dnsendpoint.name_any(),
                "patch dnsendpoint"
            );

            if !ctx.dry_run {
                dnsendpoint_api
                    .patch(
                        &dnsendpoint.name_any(),
                        &pp,
                        &Patch::Apply(dnsendpoint.clone()),
                    )
                    .await
                    .map_err(Error::Patch)?;
            }
        }

        let servicemonitor = tunnel
            .spec
            .servicemonitor
            .as_ref()
            .map(|cfdservicemonitor| {
                let servicemonitor =
                    generated_owned_servicemonitor(&ctx, &tunnel, cfdservicemonitor);
                trace!(
                    servicemonitor_name = servicemonitor.name_any(),
                    "generate servicemonitor: {servicemonitor:#?}"
                );

                let service = generated_owned_metrics_service(&ctx, &tunnel, &metrics_sock_addr);
                trace!(
                    service_name = service.name_any(),
                    "generate metrics service: {service:#?}"
                );

                (servicemonitor, service)
            });

        if let Some((ref servicemonitor, ref service)) = servicemonitor {
            let service_api: Api<Service> = Api::namespaced(
                ctx.k8s_client.clone(),
                service.namespace().as_ref().expect("namespaced"),
            );
            let servicemonitor_api: Api<ServiceMonitor> = Api::namespaced(
                ctx.k8s_client.clone(),
                servicemonitor.namespace().as_ref().expect("namespaced"),
            );

            debug!(service_name = service.name_any(), "patch metrics service");

            if !ctx.dry_run {
                service_api
                    .patch(&service.name_any(), &pp, &Patch::Apply(service.clone()))
                    .await
                    .map_err(Error::Patch)?;
            }

            debug!(
                servicemonitor_name = servicemonitor.name_any(),
                "patch servicemonitor"
            );

            if !ctx.dry_run {
                servicemonitor_api
                    .patch(
                        &servicemonitor.name_any(),
                        &pp,
                        &Patch::Apply(servicemonitor.clone()),
                    )
                    .await
                    .map_err(Error::Patch)?;
            }
        }

        cleanup_old_resources(
            &ctx,
            &tunnel,
            &ctx.namespace,
            servicemonitor.as_ref().map(|(_, service)| service),
        )
        .await?;

        let old_servicemonitor_namespace = tunnel
            .status
            .as_ref()
            .and_then(|status| status.servicemonitor_namespace.as_ref());
        for namespace in servicemonitor
            .as_ref()
            .and_then(|(servicemonitor, _)| servicemonitor.metadata.namespace.as_ref())
            .into_iter()
            .chain(old_servicemonitor_namespace)
        {
            match cleanup_old_resources(
                &ctx,
                &tunnel,
                namespace,
                servicemonitor
                    .as_ref()
                    .map(|(servicemonitor, _)| servicemonitor),
            )
            .await
            {
                Ok(()) => {}
                // The CRD doesn't exist
                Err(Error::Delete(kube::Error::Api(status))) if status.is_not_found() => {}
                Err(err) => return Err(err),
            };
        }

        let old_dnsendpoint_namespace = tunnel
            .status
            .as_ref()
            .and_then(|status| status.dnsendpoint_namespace.as_ref());
        for namespace in dnsendpoint
            .as_ref()
            .and_then(|dnsendpoint| dnsendpoint.metadata.namespace.as_ref())
            .into_iter()
            .chain(old_dnsendpoint_namespace)
        {
            match cleanup_old_resources(&ctx, &tunnel, namespace, dnsendpoint.as_ref()).await {
                Ok(()) => {}
                // The CRD doesn't exist
                Err(Error::Delete(kube::Error::Api(status))) if status.is_not_found() => {}
                Err(err) => return Err(err),
            };
        }

        cleanup_old_resources(&ctx, &tunnel, &ctx.namespace, [&configmap]).await?;
        cleanup_old_resources(&ctx, &tunnel, &ctx.namespace, [&deployment]).await?;

        let patch = Patch::Apply(json!({
            "apiVersion": CfdTunnel::api_version(&()),
            "kind": CfdTunnel::kind(&()),
            "status": CfdTunnelStatus {
                dnsendpoint_namespace: dnsendpoint
                    .as_ref()
                    .and_then(|dnsendpoint| dnsendpoint.namespace()),
                servicemonitor_namespace: servicemonitor
                    .as_ref()
                    .and_then(|(servicemonitor, _)| servicemonitor.namespace()),
                ..tunnel.status.as_ref().cloned().unwrap_or_default()
            }
        }));
        debug!(?patch, "patch status with custom resource namespaces");

        if !ctx.dry_run {
            let pp = PatchParams::apply(&ctx.name).force();
            crd_api
                .patch_status(&tunnel.name_any(), &pp, &patch)
                .await
                .map_err(Error::Patch)?;
        }

        Ok(Action::requeue(Duration::from_secs(3600)))
    };

    patch_conditions(&ctx, &tunnel, &crd_api, &result).await?;

    result
}

#[instrument(skip(tunnel, ctx))]
pub async fn cleanup(tunnel: Arc<CfdTunnel>, ctx: Arc<Context>) -> Result<Action> {
    let crd_api: Api<CfdTunnel> = Api::namespaced(
        ctx.k8s_client.clone(),
        &tunnel.namespace().expect("namespaced"),
    );

    cleanup_old_resources::<Deployment>(&ctx, &tunnel, &ctx.namespace, &[]).await?;
    cleanup_old_resources::<ConfigMap>(&ctx, &tunnel, &ctx.namespace, &[]).await?;
    cleanup_old_resources::<Secret>(&ctx, &tunnel, &ctx.namespace, &[]).await?;

    if let Some(CfdTunnelStatus {
        tunnel_id,
        conditions: _,
        dnsendpoint_namespace,
        servicemonitor_namespace,
    }) = tunnel.status.as_ref()
    {
        for namespace in servicemonitor_namespace.iter().chain([&ctx.namespace]) {
            match cleanup_old_resources::<ServiceMonitor>(&ctx, &tunnel, namespace, &[]).await {
                Ok(()) => {}
                // The CRD doesn't exist
                Err(Error::Delete(kube::Error::Api(status))) if status.is_not_found() => {}
                Err(err) => return Err(err),
            }
        }

        for namespace in dnsendpoint_namespace.iter().chain([&ctx.namespace]) {
            match cleanup_old_resources::<DNSEndpoint>(&ctx, &tunnel, namespace, &[]).await {
                Ok(()) => {}
                // The CRD doesn't exist
                Err(Error::Delete(kube::Error::Api(status))) if status.is_not_found() => {}
                Err(err) => return Err(err),
            }
        }

        if let Some(tunnel_id) = tunnel_id {
            let cf_client = cf_client_for_tunnel(&ctx, &tunnel).await?;
            let delete_tunnel_request = delete_tunnel::DeleteTunnel {
                account_identifier: &tunnel.spec.account_id,
                tunnel_id,
                params: Default::default(),
            };
            debug!(request = ?delete_tunnel_request, "delete tunnel");

            if !ctx.dry_run {
                cf_client
                    .request(&delete_tunnel_request)
                    .await
                    .map_err(Error::CfTunnel)?;
            }
        }
    }

    let patch = Patch::Merge(json!({
        "status": null,
    }));
    debug!(?patch, "remove status");
    if !ctx.dry_run {
        let pp = PatchParams::default();
        crd_api
            .patch_status(&tunnel.name_any(), &pp, &patch)
            .await
            .map_err(Error::Patch)?;
    }

    Ok(Action::await_change())
}

pub fn error_policy(
    tunnel: Arc<CfdTunnel>,
    error: &finalizer::Error<Error>,
    ctx: Arc<Context>,
) -> Action {
    let metrics_labels = metrics_labels(&ctx, &tunnel);
    counter!(
        "cfdtunnel_controller_reconciliation_errors_total",
        &metrics_labels,
    )
    .increment(1);

    match error {
        finalizer::Error::ApplyFailed(Error::CfError(_) | Error::CfTunnel(_))
        | finalizer::Error::CleanupFailed(Error::CfError(_) | Error::CfTunnel(_)) => {
            counter!(
                "cfdtunnel_controller_cloudflare_errors_total",
                &metrics_labels,
            )
            .increment(1);
        }
        _ => {}
    }

    warn!(
        tunnel = ?tunnel,
        error = error.to_string(),
        "failed to reconcile tunnel"
    );
    Action::requeue(Duration::from_secs(30))
}

async fn patch_conditions(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    crd_api: &Api<CfdTunnel>,
    result: &Result<Action>,
) -> Result<()> {
    let ready_cond = ready_condition(
        tunnel.metadata.generation,
        tunnel
            .status
            .as_ref()
            .and_then(|status| status.tunnel_id.as_ref())
            .is_some(),
    );
    let reconciled_cond = reconciled_condition(
        tunnel.metadata.generation,
        match result {
            Ok(_) => ReconcileStatus::Reconciled,
            Err(err) => ReconcileStatus::Failed(err),
        },
    );
    let patch = Patch::Apply(json!({
        "apiVersion": CfdTunnel::api_version(&()),
        "kind": CfdTunnel::kind(&()),
        "status": CfdTunnelStatus {
            conditions: Some(vec![ready_cond, reconciled_cond]),
            ..tunnel.status.as_ref().cloned().unwrap_or_default()
        }
    }));
    debug!(?patch, "patch status with conditions");

    if !ctx.dry_run {
        let pp = PatchParams::apply(&ctx.name).force();
        crd_api
            .patch_status(&tunnel.name_any(), &pp, &patch)
            .await
            .map_err(Error::Patch)?;
    }

    Ok(())
}

fn generate_owned_credentials_secret(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    credentials: &CfdTunnelCredentialsFile,
) -> Secret {
    let owner_ref = owner_ref_if_same_namespace(ctx, tunnel);
    let credentials = serde_json::to_string(credentials).expect("credentials");
    let common_labels = common_k8s_labels(ctx, tunnel);

    Secret {
        metadata: ObjectMeta {
            name: Some(base_resource_name(tunnel)),
            namespace: Some(ctx.namespace.clone()),
            owner_references: Some(owner_ref.into_iter().collect()),
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
    let owner_ref = owner_ref_if_same_namespace(ctx, tunnel);
    let common_labels = common_k8s_labels(ctx, tunnel);
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
            owner_references: Some(owner_ref.into_iter().collect()),
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
    let owner_ref = owner_ref_if_same_namespace(ctx, tunnel);
    let common_labels = common_k8s_labels(ctx, tunnel);
    let mut labels = k8s_deployment_labels(ctx, tunnel);
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
        ports: Some(vec![ContainerPort {
            name: Some("cfd-metrics".into()),
            container_port: metrics_socket_addr.port().into(),
            protocol: Some("TCP".into()),
            ..Default::default()
        }]),
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

    let uses_host_network = tunnel
        .spec
        .pod_spec_overrides
        .as_ref()
        .and_then(|s| s.host_network)
        .unwrap_or_default();
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
            sysctls: (!uses_host_network).then_some(vec![Sysctl {
                name: "net.ipv4.ping_group_range".into(),
                value: "65532 65532".into(),
            }]),
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
            owner_references: Some(owner_ref.into_iter().collect()),
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
    let owner_ref = owner_ref_if_same_namespace(ctx, tunnel);
    let metadata = ObjectMeta {
        name: Some(base_resource_name(tunnel)),
        namespace: Some(ctx.namespace.clone()),
        owner_references: Some(owner_ref.into_iter().collect()),
        labels: Some(common_k8s_labels(ctx, tunnel)),
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
                ..Default::default()
            },
            CfdTunnelExternalDnsKind::Generated { endpoints } => DNSEndpoint {
                metadata: ObjectMeta {
                    namespace: namespace.as_ref().cloned().or(metadata.namespace),
                    ..metadata
                },
                spec: DnsEndpointSpec {
                    endpoints: Some(
                        endpoints
                            .iter()
                            .cloned()
                            .map(|endpoint| DnsEndpointEndpoints {
                                dns_name: Some(endpoint.dns_name),
                                record_type: Some("CNAME".into()),
                                targets: Some(vec![format!("{}.cfargotunnel.com", tunnel_id)]),
                                record_ttl: endpoint
                                    .config
                                    .as_ref()
                                    .and_then(|e| e.record_ttl.as_ref())
                                    .cloned(),
                                labels: endpoint
                                    .config
                                    .as_ref()
                                    .and_then(|e| e.labels.as_ref())
                                    .cloned(),
                                set_identifier: endpoint
                                    .config
                                    .as_ref()
                                    .and_then(|e| e.set_identifier.as_ref())
                                    .cloned(),
                                provider_specific: endpoint
                                    .config
                                    .as_ref()
                                    .and_then(|e| e.provider_specific.as_ref())
                                    .cloned(),
                            })
                            .collect(),
                    ),
                },
                ..Default::default()
            },
        },
    }
}

fn generated_owned_metrics_service(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    metrics_socket_addr: &SocketAddr,
) -> Service {
    let owner_ref = owner_ref_if_same_namespace(ctx, tunnel);
    let common_labels = common_k8s_labels(ctx, tunnel);
    let mut deployment_labels = k8s_deployment_labels(ctx, tunnel);
    deployment_labels.extend(common_labels);
    let metadata = ObjectMeta {
        name: Some(format!("{}-metrics", base_resource_name(tunnel))),
        namespace: Some(ctx.namespace.clone()),
        owner_references: Some(owner_ref.into_iter().collect()),
        labels: Some(deployment_labels.clone()),
        ..Default::default()
    };

    Service {
        metadata,
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".into()),
            cluster_ip: Some("None".into()),
            selector: Some(deployment_labels),
            ports: Some(vec![ServicePort {
                name: Some("cfd-metrics".into()),
                port: metrics_socket_addr.port().into(),
                protocol: Some("TCP".into()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn generated_owned_servicemonitor(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    service_monitor: &CfdServiceMonitor,
) -> ServiceMonitor {
    let owner_ref = owner_ref_if_same_namespace(ctx, tunnel);
    let common_labels = common_k8s_labels(ctx, tunnel);
    let mut deployment_labels = k8s_deployment_labels(ctx, tunnel);
    deployment_labels.extend(common_labels);
    let metadata = ObjectMeta {
        name: Some(format!("{}-metrics", base_resource_name(tunnel))),
        namespace: service_monitor
            .namespace
            .as_ref()
            .or_else(|| Some(&ctx.namespace))
            .cloned(),
        owner_references: Some(owner_ref.into_iter().collect()),
        labels: Some(deployment_labels.clone()),
        ..Default::default()
    };

    let base_config = service_monitor.config.clone().unwrap_or_default();

    ServiceMonitor {
        metadata,
        spec: ServiceMonitorSpec {
            namespace_selector: Some(ServiceMonitorNamespaceSelector {
                match_names: Some(vec![ctx.namespace.clone()]),
                ..Default::default()
            }),
            selector: ServiceMonitorSelector {
                match_labels: Some(deployment_labels),
                ..Default::default()
            },
            endpoints: vec![ServiceMonitorEndpoints {
                port: Some("cfd-metrics".into()),
                ..Default::default()
            }],
            ..base_config
        },
        ..Default::default()
    }
}

fn owner_ref_if_same_namespace(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
) -> Option<OwnerReference> {
    tunnel.namespace().as_ref().and_then(|namespace| {
        if namespace == &ctx.namespace {
            tunnel.controller_owner_ref(&())
        } else {
            None
        }
    })
}

async fn cleanup_old_resources<'a, K>(
    ctx: &Arc<Context>,
    tunnel: &Arc<CfdTunnel>,
    namespace: &str,
    current_resources: impl IntoIterator<Item = &'a K>,
) -> Result<()>
where
    K: Clone + DeserializeOwned + Debug,
    K: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope> + 'a,
    <K as kube::Resource>::DynamicType: std::default::Default,
{
    let api: Api<K> = Api::namespaced(ctx.k8s_client.clone(), namespace);
    let common_labels = common_k8s_labels(ctx, tunnel);
    let resource_name = std::any::type_name::<K>();

    if !ctx.dry_run {
        let result = api
            .delete_collection(
                &DeleteParams::default(),
                &ListParams::default()
                    .fields(
                        &current_resources
                            .into_iter()
                            .map(|r| format!("metadata.name!={}", r.name_any()))
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                    .labels_from(&Selector::from_iter(common_labels.clone())),
            )
            .await
            .map_err(Error::Delete)?;

        debug!(
            namespace,
            resource_name,
            ?common_labels,
            ?result,
            "cleanup old resources"
        );
    } else {
        debug!(
            namespace,
            resource_name,
            ?common_labels,
            "cleanup old resources"
        );
    }

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

fn common_k8s_labels(ctx: &Arc<Context>, tunnel: &Arc<CfdTunnel>) -> BTreeMap<String, String> {
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

fn k8s_deployment_labels(_: &Arc<Context>, tunnel: &Arc<CfdTunnel>) -> BTreeMap<String, String> {
    [
        ("app.kubernetes.io/name".into(), "cloudflared".into()),
        (
            "app.kubernetes.io/instance".into(),
            base_resource_name(tunnel),
        ),
    ]
    .into()
}

fn metrics_labels(ctx: &Arc<Context>, tunnel: &Arc<CfdTunnel>) -> [(&'static str, String); 3] {
    [
        ("operator_namespace", ctx.namespace.clone()),
        ("resource_name", tunnel.name_any()),
        (
            "resource_namespace",
            tunnel.namespace().expect("namespaced"),
        ),
    ]
}

fn ready_condition(observed_generation: Option<i64>, ready: bool) -> Condition {
    Condition {
        status: if ready { "True".into() } else { "False".into() },
        type_: "Ready".into(),
        reason: if ready {
            "CfTunnelCreated".into()
        } else {
            "".into()
        },
        message: "".into(),
        observed_generation,
        last_transition_time: k8s_openapi::jiff::Timestamp::now().into(),
    }
}

enum ReconcileStatus<'a> {
    Failed(&'a Error),
    Reconciled,
}
fn reconciled_condition(observed_generation: Option<i64>, status: ReconcileStatus) -> Condition {
    Condition {
        status: match status {
            ReconcileStatus::Failed(_) => "False".into(),
            ReconcileStatus::Reconciled => "True".into(),
        },
        type_: "Reconciled".into(),
        reason: match status {
            ReconcileStatus::Failed(_) => "ReconcileFailed".into(),
            ReconcileStatus::Reconciled => "ReconcileSucceeded".into(),
        },
        message: match status {
            ReconcileStatus::Failed(err) => err.to_string(),
            _ => "".into(),
        },
        observed_generation,
        last_transition_time: k8s_openapi::jiff::Timestamp::now().into(),
    }
}
