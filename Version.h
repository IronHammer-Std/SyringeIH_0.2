#pragma once

#define VMAJOR 0
#define VMINOR 3
#define VRELEASE 0
#define VBUILD 99

#define PRODUCT_VERSION VMAJOR, VMINOR, VRELEASE, VBUILD
#define FILE_VERSION VMAJOR, VMINOR, VRELEASE, VBUILD

#define StrImpl(x) #x
#define Str(x) StrImpl(x)

#define CUSTOM_VERSION_STR "0.3 Release"

#ifdef CUSTOM_VERSION_STR
	#define VERSION_STR CUSTOM_VERSION_STR
	constexpr auto const VersionString = "SyringeIH " VERSION_STR;
	constexpr auto const VersionLString = L"SyringeIH " VERSION_STR;
	#define PRODUCT_VERSION_STR CUSTOM_VERSION_STR
	#define FILE_VERSION_STR CUSTOM_VERSION_STR
#else
	#if VBUILD == 0
		#if VRELEASE == 0
			#define VERSION_STR  Str(VMAJOR) "." Str(VMINOR)
		#else
			#define VERSION_STR  Str(VMAJOR) "." Str(VMINOR) "." Str(VRELEASE)
		#endif
	#else
		#if VRELEASE == 0
			#define VERSION_STR  Str(VMAJOR) "." Str(VMINOR) "b" Str(VBUILD)
		#else
			#define VERSION_STR  Str(VMAJOR) "." Str(VMINOR) "." Str(VRELEASE) "b" Str(VBUILD)
		#endif
	#endif
	constexpr auto const VersionString = "SyringeIH " VERSION_STR;
	constexpr auto const VersionLString = L"SyringeIH " VERSION_STR;
	#define PRODUCT_VERSION_STR Str(VMAJOR) "." Str(VMINOR) "." Str(VRELEASE) "." Str(VBUILD)
	#define FILE_VERSION_STR Str(VMAJOR) "." Str(VMINOR) "." Str(VRELEASE) "." Str(VBUILD)
#endif





const int VMajor = VMAJOR;
const int VMinor = VMINOR;
const int VRelease = VRELEASE;
const int VBuild = VBUILD;
