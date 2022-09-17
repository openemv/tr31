# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cmake

DESCRIPTION="TR-31 library and tools"
HOMEPAGE="https://github.com/openemv/tr31"
if [[ "${PV}" == *9999 ]] ; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/openemv/tr31.git"
	EGIT_BRANCH="master"
else
	SRC_URI="https://github.com/openemv/tr31/releases/download/${PV}/${P}-src.tar.gz -> ${P}.tar.gz"
fi

LICENSE="LGPL-2.1"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="+mbedtls openssl doc test"
REQUIRED_USE="|| ( mbedtls openssl )"
RESTRICT="!test? ( test )"

BDEPEND="
	doc? ( app-doc/doxygen )
"

RDEPEND="
	mbedtls? ( net-libs/mbedtls )
	openssl? ( dev-libs/openssl:0/1.1 )
"
DEPEND="
	${RDEPEND}
"

src_prepare() {
	cmake_src_prepare
}

src_configure() {
	local mycmakeargs=(
		$(cmake_use_find_package mbedtls MbedTLS)
		$(cmake_use_find_package openssl OpenSSL)
		-DBUILD_DOCS=$(usex doc)
		-DBUILD_TESTING=$(usex test)
	)

	cmake_src_configure
}

src_test() {
	cmake_src_test
}

DOCS=( README.md LICENSE )
