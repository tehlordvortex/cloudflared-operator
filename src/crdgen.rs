use kube::CustomResourceExt;

fn main() {
    print!(
        "{}",
        serde_yaml::to_string(&operator::CfdTunnel::crd()).unwrap()
    );
}
