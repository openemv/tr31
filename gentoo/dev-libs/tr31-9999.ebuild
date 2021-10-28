# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cmake

DESCRIPTION="TR-31 library and tools"
HOMEPAGE="https://github.com/ono-connect/tr31"
if [[ "${PV}" == *9999 ]] ; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/ono-connect/tr31.git"
	EGIT_BRANCH="master"
else
	SRC_URI="https://github.com/ono-connect/tr31/archive/${PV}.tar.gz -> ${P}.tar.gz"
fi

LICENSE="LGPL-2.1"
SLOT="0"
KEYWORDS="~amd64 ~x86"

RDEPEND="
	dev-libs/openssl:0/1.1
"
DEPEND="
	${RDEPEND}
"

src_configure() {
	cmake_src_configure
}
