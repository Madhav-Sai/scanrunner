# Controlled Docker detection lab

Run the manually dispatched **Controlled Docker detection lab** GitHub Actions workflow to exercise the production ScanRunner CLI against four owned Samba containers. The matrix combines SMBv1 enabled or disabled with SMB signing optional or required. Each endpoint provides two labeled checks, totaling eight cases.

The workflow accepts either Debian Bookworm or Trixie as its runtime. Run each separately to measure compatibility across independently resolved Nmap and Samba versions. Repeated configurations remain correlated, and each execution retains its own versions and evidence.

The runtime network is internal, with fixed addresses and no published service ports. The scanner drops Linux capabilities and uses TCP connect scanning. Containers and their network are removed after evidence upload.

Ground truth combines effective Samba settings and independent SMB1/SMB2 wire negotiation. Configurations, binary and script hashes, image identities, raw negotiation bytes, scanner artifacts and execution failures are retained in the workflow artifact. Each execution uses a fresh evidence directory. The benchmark uses production normalization and rules, including abstentions for missing usable scanner evidence.

Local reproduction requires Docker Compose and a writable, fresh output directory. Set `LAB_OUTPUT_DIR`, `LAB_UID` and `LAB_GID` for the local environment, then run the workflow's Compose commands from the repository root. The workflow records the resolved runtime versions because package repositories and base-image tags can change.

Eight cases measure these four Samba configurations and two supported SMB checks. Broader service, operating-system, authentication and network conditions require additional independently verified cases. A successful run also executes the gated real localhost Nmap regression.
