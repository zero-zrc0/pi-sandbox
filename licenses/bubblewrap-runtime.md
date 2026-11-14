# Bubblewrap runtime distribution

Bubblewrap is distributed under LGPLv2+. The Linux runtime archive includes the Bubblewrap 0.13.1 license and the license for statically linked libcap 2.75 in `bwrap.LICENSE`. It records the Bubblewrap version and source commit used to build the binary.

The runtime archive contains a regular non-setuid executable. It does not install files into system directories or change file ownership or permissions outside the plugin runtime directory.

Upstream project: <https://github.com/containers/bubblewrap>
