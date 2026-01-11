#powershell -ExecutionPolicy ByPass -File build.ps1
param(
  [string]$libcdoc = $PSScriptRoot,
  [string]$platform = "x64",
  [string]$build_number = $(if ($null -eq $env:BUILD_NUMBER) {"0"} else {$env:BUILD_NUMBER}),
  [string]$git = "git.exe",
  [string]$vcpkg = "vcpkg\vcpkg.exe",
  [string]$vcpkg_dir = (split-path -parent $vcpkg),
  [string]$vcpkg_installed = $libcdoc,
  [string]$vcpkg_triplet = "x64-windows",
  [string]$vcpkg_installed_platform = "$vcpkg_installed\vcpkg_installed",
  [string]$cmake = "cmake.exe",
  [string]$generator = "Visual Studio 17 2022",
  [switch]$RunTests = $false
)

if(!(Test-Path -Path $vcpkg)) {
  & $git clone https://github.com/microsoft/vcpkg.git $vcpkg_dir
  & $vcpkg_dir\bootstrap-vcpkg.bat
}

$cmakeext = @()
if($platform -eq "arm64" -and $env:VSCMD_ARG_HOST_ARCH -ne "arm64") {
  $cmakeext += "-DCMAKE_DISABLE_FIND_PACKAGE_Python3=yes"
  $RunTests = $false
}
if($RunTests) {
  $cmakeext += "-DVCPKG_MANIFEST_FEATURES=tests"
}

$buildpath = "build"

& $cmake --fresh -B $buildpath -S . "-G$generator" $cmakeext `
    "--toolchain $vcpkg_dir/scripts/buildsystems/vcpkg.cmake" `
    "-DVCPKG_INSTALLED_DIR=$vcpkg_installed_platform" `
    "-DVCPKG_TARGET_TRIPLET=$vcpkg_triplet"

foreach($type in @("Debug", "RelWithDebInfo")) {
    "==================="
    "Build Configuration: " + $type
    "==================="
    & $cmake --build $buildpath --config $type
#    & $cmake --install $buildpath
}

if($RunTests) {
    Push-Location "$libcdoc\$buildpath"
    ctest -V -C Debug
    Pop-Location
}
