# Linux namespace integration

`../../scripts/namespace-smoke.sh` creates an isolated client/proxy/target
topology with veth links, explicit routes, and deterministic test addresses.
It skips unless `MASKMAN_NETWORK_NAMESPACE=1` and the runner has Linux network
administration privileges. Pass a command after the script to execute it in the
proxy namespace. CI must record a skipped privileged job separately from a
passing data-plane test.
