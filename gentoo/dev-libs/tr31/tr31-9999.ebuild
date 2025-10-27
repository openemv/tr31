# Copyright 1999-2025 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cmake

DESCRIPTION="Key block library and tools for ANSI X9.143, ASC X9 TR-31 and ISO 20038"
HOMEPAGE="https://github.com/openemv/tr31"
if [[ "${PV}" == *9999 ]] ; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/openemv/tr31.git"
	EGIT_BRANCH="master"
else
	SRC_URI="https://github.com/openemv/tr31/releases/download/${PV}/${P}-src.tar.gz -> ${P}.tar.gz"
fi

LICENSE="LGPL-2.1+ tools? ( GPL-3+ )"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="+mbedtls openssl +tools doc test"
REQUIRED_USE="|| ( mbedtls openssl )"
RESTRICT="!test? ( test )"

BDEPEND="
	doc? ( app-text/doxygen )
"

RDEPEND="
	mbedtls? ( net-libs/mbedtls )
	openssl? ( dev-libs/openssl )
"
DEPEND="
	${RDEPEND}
"

src_prepare() {
	cmake_src_prepare

	# Remove dirty suffix because Gentoo modifies CMakeLists.txt
	sed -i -e 's/--dirty//' CMakeLists.txt || die "Failed to remove dirty suffix"
}

src_configure() {
	local mycmakeargs=(
		$(cmake_use_find_package mbedtls MbedTLS)
		$(cmake_use_find_package openssl OpenSSL)
		-DBUILD_TR31_TOOL=$(usex tools)
		-DBUILD_DOCS=$(usex doc)
		-DBUILD_TESTING=$(usex test)
	)

	cmake_src_configure
}

src_test() {
	cmake_src_test
}

DOCS=( README.md LICENSE )
