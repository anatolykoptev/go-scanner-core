# Changelog

## [0.2.2](https://github.com/anatolykoptev/go-scanner-core/compare/v0.2.1...v0.2.2) (2026-07-10)


### Fixed

* **authz:** consolidate domain normalization onto target.NormalizeHostname ([3c19f74](https://github.com/anatolykoptev/go-scanner-core/commit/3c19f74d51212947a54873e473ba2a90336c7983))
* **target:** reject URL-authority/control chars in hostname normalization (SSRF) ([15caa55](https://github.com/anatolykoptev/go-scanner-core/commit/15caa55fed814acf71ec6b0aa210a0e9cf277044))


### Changed

* single IDNA normalizer + hosted CI ([0435880](https://github.com/anatolykoptev/go-scanner-core/commit/0435880c0d0ef24c218b596dd7b82b9bfbde09b3))


### Documentation

* **readme:** drop internal-repo references, present as a standalone library ([#9](https://github.com/anatolykoptev/go-scanner-core/issues/9)) ([9d6fceb](https://github.com/anatolykoptev/go-scanner-core/commit/9d6fceb9d0a2865bfb7893153ae6731c432f6a0d))
* **readme:** drop release automation note, keep client-facing content ([#12](https://github.com/anatolykoptev/go-scanner-core/issues/12)) ([86f1428](https://github.com/anatolykoptev/go-scanner-core/commit/86f1428141bf4547d16d3d09e298ecdb9f995502))

## [0.2.1](https://github.com/anatolykoptev/go-scanner-core/compare/v0.2.0...v0.2.1) (2026-07-10)


### Added

* portfolio-grade hardening, docs, fuzzing, examples & CI ([fd455ab](https://github.com/anatolykoptev/go-scanner-core/commit/fd455ab91af0d710b1212d1162d55ba78a05108c))


### Fixed

* **target:** hard-block Alibaba Cloud IMDS endpoint 100.100.100.200 ([44a7319](https://github.com/anatolykoptev/go-scanner-core/commit/44a7319466a31b2a22d65473caf521b9fa84dd50))


### Documentation

* **godoc:** add doc.go per package, complete exported-symbol doc comments ([d769445](https://github.com/anatolykoptev/go-scanner-core/commit/d769445257f205d4550f389965f6866767d89b53))
* **license:** add Apache-2.0 with copyright 2026 Anatoly Koptev ([bc7b17a](https://github.com/anatolykoptev/go-scanner-core/commit/bc7b17ac66e6869d4759c3807b110374b80d9999))
* **readme:** add badges, Design & threat model section, fix stale snippet ([849849e](https://github.com/anatolykoptev/go-scanner-core/commit/849849e1991c39be38aabd23005367b275d73bcc))
* **security:** add responsible-disclosure policy ([c25adda](https://github.com/anatolykoptev/go-scanner-core/commit/c25addae65cadc9b62fa989bdd2d6dfe030ef4d7))

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
