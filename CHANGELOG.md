# Changelog

## [0.2.0](https://github.com/anatolykoptev/go-scanner-core/compare/v0.1.1...v0.2.0) (2026-07-10)


* set up release-please automated releases ([86ea3da](https://github.com/anatolykoptev/go-scanner-core/commit/86ea3daed1d9ccaffe9cef37e5367c6ad65a4b36))


### Fixed

* **audit:** preserve segments and hash chain across log rotation ([81533a1](https://github.com/anatolykoptev/go-scanner-core/commit/81533a159c785919601e62d550750a32b7155bdc))
* **authz,audit:** harden authz hard-block, danger gate, audit rotation ([81f5667](https://github.com/anatolykoptev/go-scanner-core/commit/81f56671a8beacbc7b38dc85f28440517a68498f))
* **authz:** add audited opt-in allow_internal bypass for hard-block ([6f8608a](https://github.com/anatolykoptev/go-scanner-core/commit/6f8608ac8a6bb473e4f3b9b2991b8ae64fdf45bb))
* **authz:** enforce target hard-block in CheckTarget (SSRF) ([89035f3](https://github.com/anatolykoptev/go-scanner-core/commit/89035f307e9da55f05d1d1bd6e473e857a72541b))
* **authz:** fail-closed danger gate on composite profile strings ([050c1ea](https://github.com/anatolykoptev/go-scanner-core/commit/050c1ea9adb7954bed65a2d438ce661188892eb8))
* **authz:** fail-closed danger gate on nmap all/boolean script grammar ([0a7a5e5](https://github.com/anatolykoptev/go-scanner-core/commit/0a7a5e5c69e93cf6de95a3530112dedf90376fb2))
* **deps:** bump golang.org/x/net to close GO-2026-5026 on the idna auth path ([12b77eb](https://github.com/anatolykoptev/go-scanner-core/commit/12b77eb00e46f225bb2a54d926bf46d6f4933952))
* **target:** hard-block IPv6 link-local and IMDSv6 endpoints ([d6b5644](https://github.com/anatolykoptev/go-scanner-core/commit/d6b56443ba4881758822085d730fc5f1c235fe76))


### Changed

* **authz:** drop unreachable empty-token guard in profile tokenizer ([408dbc5](https://github.com/anatolykoptev/go-scanner-core/commit/408dbc55090a34c75014175608b0398ff7426e3a))


### Documentation

* correct consumer/origin (extracted from go-wowa, migration planned) and target/ hard-block role ([78ba779](https://github.com/anatolykoptev/go-scanner-core/commit/78ba77993b7aac39844544178e7bc23e7a4ef200))
