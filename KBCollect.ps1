function Get-CollectKB(){
    # 1. 搜集所有的KB补丁
    $KBArray = @()
    $KBArray = Get-HotFix|ForEach-Object {$_.HotFixId}
    $test = $KBArray|ConvertTo-Json
    return $test
}
function Get-BasicInfo(){
    # 1. 操作系统
    # $windowsProductName = (Get-ComputerInfo).WindowsProductName
    $windowsProductName = (Get-CimInstance Win32_OperatingSystem).Caption
    # 2. 操作系统版本
    $windowsVersion = (Get-ComputerInfo).WindowsVersion
    $basicInfo = "{""windowsProductName"":""$windowsProductName"",""windowsVersion"":""$windowsVersion""}"
    return $basicInfo
    
}
$basicInfo = Get-BasicInfo
$KBList = Get-CollectKB
$KBResult = "{""basicInfo"":$basicInfo,""KBList"":$KBList}"
$KBResult|Out-File KB.json -encoding utf8
