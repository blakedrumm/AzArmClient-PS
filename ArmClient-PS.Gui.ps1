<#
.SYNOPSIS
Fluent desktop console for ArmClient-PS.

.DESCRIPTION
ArmClient-PS.Gui.ps1 is a standalone WPF front end for ArmClient-PS.ps1. It loads the tool as a
library inside a dedicated background runspace, presents the built-in operation catalog, builds
Azure Resource Manager requests, and streams live log output without blocking the UI thread.

This file never modifies ArmClient-PS.ps1. It drives the tool through PowerShell's dynamic scoping
by shadowing the script's own parameter variables from a wrapper function, which keeps every
validation, redaction, retry, and long-running-operation behavior of the core tool intact.

.PARAMETER ScriptPath
Full path to ArmClient-PS.ps1. Defaults to the copy sitting beside this file.

.PARAMETER Theme
Initial theme. Auto follows the Windows apps theme.

.NOTES
Script Name: ArmClient-PS.Gui.ps1
Author: Blake Drumm (blakedrumm@microsoft.com)
Requirements: Windows PowerShell 5.1 or PowerShell 7.x, WPF, and a complete ArmClient-PS package.
Security: Responses are redacted by default. Raw content requires an explicit, time-limited reveal.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ScriptPath,
    [ValidateSet('Auto', 'Light', 'Dark')][string]$Theme = 'Auto',
    [switch]$Relaunched
)

# ==============================================================================
# REGION 1  Host guard
# WPF needs a single-threaded apartment, and Az binds its assemblies once per
# process, so a session that already imported Az.Accounts can never load the
# bundled version. Both conditions are fixed by relaunching into a clean host.
# ==============================================================================

$GuiRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$GuiFile = if ($PSCommandPath) { $PSCommandPath } else { Join-Path $GuiRoot 'ArmClient-PS.Gui.ps1' }

function Test-AzAlreadyResident {
    if (Get-Module -Name 'Az.Accounts') { return $true }
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $name = $assembly.GetName().Name
        if ($name -eq 'Az.Accounts' -or
            $name -eq 'Microsoft.Azure.PowerShell.Cmdlets.Accounts' -or
            $name -like 'Microsoft.Azure.PowerShell.Authentication*' -or
            $name -like 'Microsoft.Azure.PowerShell.Common*') { return $true }
    }
    return $false
}

$isSta = ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')
$azResident = Test-AzAlreadyResident

if (-not $isSta -or $azResident) {
    if ($Relaunched) {
        # The child already runs -NoProfile, so reaching this means something in the
        # machine configuration loads Az before the script does.
        $detail = if (-not $isSta) { 'this host will not start in a single-threaded apartment' }
        else { 'Az.Accounts is loaded by machine or host configuration before this script runs' }
        $message = "ArmClient-PS cannot start cleanly because $detail." +
        [Environment]::NewLine + [Environment]::NewLine +
        'Start a new PowerShell session with -NoProfile and run the tool again.'
        Write-Warning $message
        # This process was started with a hidden console, so a warning alone reaches nobody.
        try {
            Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
            [void][System.Windows.MessageBox]::Show($message, 'ArmClient-PS', 'OK', 'Warning')
        }
        catch { }
        return
    }

    # $PSHOME beats the process image: an SDK-hosted app reports edition Core but is
    # not pwsh, and $env:WINDIR is both mutable and WOW64-redirected.
    $hostLeaf = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $hostExe = if ($PSHOME) { Join-Path $PSHOME $hostLeaf } else { $null }
    if (-not $hostExe -or -not (Test-Path -LiteralPath $hostExe -PathType Leaf)) {
        $hostExe = Get-Command -Name $hostLeaf -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty Source
    }
    if (-not $hostExe) {
        Write-Error "ArmClient-PS could not locate $hostLeaf to start a clean PowerShell host."
        return
    }

    # Start-Process joins the argument array with spaces, so a quote or trailing
    # backslash in this user-supplied value would inject extra child parameters.
    if ($PSBoundParameters.ContainsKey('ScriptPath') -and
        ($ScriptPath.Contains('"') -or $ScriptPath.EndsWith('\'))) {
        Write-Error 'ScriptPath must be a plain file path containing no double quote and no trailing backslash.'
        return
    }

    $relaunch = @('-NoProfile', '-STA', '-File', ('"{0}"' -f $GuiFile), '-Relaunched')
    if ($PSBoundParameters.ContainsKey('ScriptPath')) { $relaunch += @('-ScriptPath', ('"{0}"' -f $ScriptPath)) }
    if ($PSBoundParameters.ContainsKey('Theme')) { $relaunch += @('-Theme', $Theme) }

    if ($azResident) {
        Write-Host 'Az.Accounts is already loaded in this session, so ArmClient-PS is starting in a clean PowerShell process.' -ForegroundColor Yellow
    }
    try {
        $child = Start-Process -FilePath $hostExe -ArgumentList $relaunch -WindowStyle Hidden -PassThru -ErrorAction Stop
        # The child's console is hidden, so an immediate failure would otherwise be silent.
        if ($child.WaitForExit(2000)) {
            Write-Error ("ArmClient-PS exited immediately with code {0}. Run it directly to see the error: {1} -NoProfile -File `"{2}`"" -f $child.ExitCode, $hostLeaf, $GuiFile)
        }
    }
    catch {
        Write-Error "ArmClient-PS could not start a clean PowerShell host. $($_.Exception.Message)"
    }
    return
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml
# Windows PowerShell needs this before ProtectedData resolves; PowerShell 7 has it built in.
try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }

if (-not $ScriptPath) { $ScriptPath = Join-Path $GuiRoot 'ArmClient-PS.ps1' }

# ==============================================================================
# REGION 2  Application state
# One synchronized store. UI code reads and writes it on the dispatcher thread
# only; the worker communicates through PowerShell streams, never through this.
# ==============================================================================

$script:App = [hashtable]::Synchronized(@{
        ScriptPath      = $ScriptPath
        Version         = ''
        Catalog         = @()
        CatalogInfo     = $null
        SelectedDiscovered = $null
        SelectedPreset  = $null
        ScopeSuppress   = $false
        ParamGeneration = @{}
        DeployedOnly    = $false
        DeployedTypes   = $null
        TenantNames     = @{}
        ParamBoxes      = @{}
        Defaults        = [ordered]@{}
        LoadingControls = [System.Collections.Generic.List[object]]::new()
        LoadingTimer    = $null
        LoadingPhase    = 0
        Runspace        = $null
        Worker          = $null
        WorkerAsync     = $null
        InfoIndex       = 0
        WarnIndex       = 0
        ErrorIndex      = 0
        Pump            = $null
        Busy            = $false
        Kind            = ''
        Started         = $null
        Context         = $null
        Theme           = 'Light'
        RawResponse     = ''
        RedactedText    = ''
        ResponseIsSecret = $false
        RevealTimer     = $null
        Revealed        = $false
        LogLines        = [System.Collections.Generic.List[string]]::new()
        MaxLogLines     = 4000
        PendingLog      = [System.Text.StringBuilder]::new()
        Ui              = @{}

        # Catalog search. Blobs/names are pre-uppercased once so the hot path is
        # pure Ordinal substring work; HitBuf and LastHits are allocated once and
        # reused, because per-item List.Add costs more than the search itself.
        PresetItems     = @()
        PresetBlobs     = [string[]]@()
        OpItems         = @()
        OpBlobs         = [string[]]@()
        OpNamesUpper    = [string[]]@()
        OpLabels        = [string[]]@()
        OpMethods       = [string[]]@()
        OpTips          = [string[]]@()
        OpBrushes       = [object[]]@()
        BrowseRoots     = $null
        HitBuf          = [int[]]@()
        LastHits        = [int[]]@()
        LastHitCount    = -1
        LastTokens      = [string[]]@()
        SearchTimer     = $null
        SearchPending   = ''
        SearchApplied   = $null   # $null, not '', so the first unfiltered build always runs
        SearchSuppress  = $false
    })

$script:Environments = @('AzureCloud', 'AzureUSGovernment', 'AzureChinaCloud', 'AzureUSNat', 'AzureUSSec')
# Built from its code point so this file stays pure ASCII. PowerShell 5.1 decodes a
# BOM-less file as ANSI, which would otherwise corrupt the literal character.
$script:MiddleDot = [string][char]0x00B7
$script:MaxRenderChars = 400000     # Above this the response is truncated for display only.
$script:RevealSeconds = 30
$script:MaxCatalogResults = 300     # Search results are capped so the tree never renders thousands of nodes.
$script:MinDerivedSearchLength = 3

# Operations whose response bodies are secret-bearing regardless of content shape.
$script:SecretPathPattern = '(?i)/(listKeys|listSecrets|listCredentials|listConnectionStrings|listAccountSas|listServiceSas|regenerateKey|listQueryKeys|listAdminKeys)(/|\?|$)'

# ==============================================================================
# REGION 3  Small helpers
# ==============================================================================

function Get-SafeProperty {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-Bool {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    return [bool]$Value
}

function Get-WindowsUsesLightTheme {
    try {
        $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
        $item = Get-ItemProperty -Path $key -Name 'AppsUseLightTheme' -ErrorAction Stop
        return ([int]$item.AppsUseLightTheme -ne 0)
    }
    catch { return $true }
}

# ==============================================================================
# REGION 4  Design system
# Two palettes plus one style sheet. Every style references theme colors through
# DynamicResource so swapping the merged palette re-themes the live window.
# ==============================================================================

$XamlPaletteLight = @'
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <SolidColorBrush x:Key="Bg.App"          Color="#F3F3F3"/>
  <SolidColorBrush x:Key="Bg.Layer"        Color="#FFFFFF"/>
  <SolidColorBrush x:Key="Bg.LayerAlt"     Color="#FAFAFA"/>
  <SolidColorBrush x:Key="Bg.Subtle"       Color="#F5F5F5"/>
  <SolidColorBrush x:Key="Bg.Control"      Color="#FFFFFF"/>
  <SolidColorBrush x:Key="Bg.ControlHover" Color="#F5F5F5"/>
  <SolidColorBrush x:Key="Bg.ControlPress" Color="#EDEDED"/>
  <SolidColorBrush x:Key="Bg.Selected"     Color="#EDF4FC"/>
  <SolidColorBrush x:Key="Stroke.Default"  Color="#E1E1E1"/>
  <SolidColorBrush x:Key="Stroke.Control"  Color="#D1D1D1"/>
  <SolidColorBrush x:Key="Stroke.Strong"   Color="#8A8A8A"/>
  <SolidColorBrush x:Key="Text.Primary"    Color="#1A1A1A"/>
  <SolidColorBrush x:Key="Text.Secondary"  Color="#5D5D5D"/>
  <SolidColorBrush x:Key="Text.Tertiary"   Color="#767676"/>
  <SolidColorBrush x:Key="Text.OnAccent"   Color="#FFFFFF"/>
  <SolidColorBrush x:Key="Accent.Default"  Color="#0078D4"/>
  <SolidColorBrush x:Key="Accent.Hover"    Color="#106EBE"/>
  <SolidColorBrush x:Key="Accent.Press"    Color="#005A9E"/>
  <SolidColorBrush x:Key="Accent.Subtle"   Color="#EFF6FC"/>
  <SolidColorBrush x:Key="State.Danger"    Color="#C42B1C"/>
  <SolidColorBrush x:Key="State.DangerBg"  Color="#FDF3F4"/>
  <SolidColorBrush x:Key="State.Warning"   Color="#9D5D00"/>
  <SolidColorBrush x:Key="State.WarningBg" Color="#FFF9F5"/>
  <SolidColorBrush x:Key="State.Success"   Color="#0F7B0F"/>
  <SolidColorBrush x:Key="State.SuccessBg" Color="#F1FAF1"/>
  <SolidColorBrush x:Key="State.Neutral"   Color="#5D5D5D"/>
  <SolidColorBrush x:Key="State.NeutralBg" Color="#F5F5F5"/>
  <SolidColorBrush x:Key="Editor.Bg"       Color="#FCFCFC"/>
</ResourceDictionary>
'@

$XamlPaletteDark = @'
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <SolidColorBrush x:Key="Bg.App"          Color="#202020"/>
  <SolidColorBrush x:Key="Bg.Layer"        Color="#2B2B2B"/>
  <SolidColorBrush x:Key="Bg.LayerAlt"     Color="#272727"/>
  <SolidColorBrush x:Key="Bg.Subtle"       Color="#333333"/>
  <SolidColorBrush x:Key="Bg.Control"      Color="#333333"/>
  <SolidColorBrush x:Key="Bg.ControlHover" Color="#3B3B3B"/>
  <SolidColorBrush x:Key="Bg.ControlPress" Color="#2E2E2E"/>
  <SolidColorBrush x:Key="Bg.Selected"     Color="#0E3A5C"/>
  <SolidColorBrush x:Key="Stroke.Default"  Color="#3A3A3A"/>
  <SolidColorBrush x:Key="Stroke.Control"  Color="#4A4A4A"/>
  <SolidColorBrush x:Key="Stroke.Strong"   Color="#6E6E6E"/>
  <SolidColorBrush x:Key="Text.Primary"    Color="#FFFFFF"/>
  <SolidColorBrush x:Key="Text.Secondary"  Color="#C7C7C7"/>
  <SolidColorBrush x:Key="Text.Tertiary"   Color="#A0A0A0"/>
  <!-- Windows 11 puts dark text on a light accent in dark theme. White here measures 2.81:1. -->
  <SolidColorBrush x:Key="Text.OnAccent"   Color="#0A0A0A"/>
  <SolidColorBrush x:Key="Accent.Default"  Color="#479EF5"/>
  <SolidColorBrush x:Key="Accent.Hover"    Color="#62ABF5"/>
  <SolidColorBrush x:Key="Accent.Press"    Color="#2886DE"/>
  <SolidColorBrush x:Key="Accent.Subtle"   Color="#12314A"/>
  <SolidColorBrush x:Key="State.Danger"    Color="#C42B1C"/>
  <SolidColorBrush x:Key="State.DangerBg"  Color="#442726"/>
  <SolidColorBrush x:Key="State.Warning"   Color="#8F5700"/>
  <SolidColorBrush x:Key="State.WarningBg" Color="#433519"/>
  <SolidColorBrush x:Key="State.Success"   Color="#107C10"/>
  <SolidColorBrush x:Key="State.SuccessBg" Color="#213D1D"/>
  <SolidColorBrush x:Key="State.Neutral"   Color="#5A5A5A"/>
  <SolidColorBrush x:Key="State.NeutralBg" Color="#2F2F2F"/>
  <SolidColorBrush x:Key="Editor.Bg"       Color="#252525"/>
</ResourceDictionary>
'@

# ==============================================================================
# REGION 5  Window markup
# Single-quoted here-string: nothing is interpolated, so no user or response data
# can ever reach the XAML parser.
# ==============================================================================

$script:XamlMarkup = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="ArmClient-PS" Height="880" Width="1360" MinHeight="560" MinWidth="900"
        WindowStartupLocation="Manual"
        UseLayoutRounding="True" SnapsToDevicePixels="True"
        TextOptions.TextFormattingMode="Ideal" TextOptions.TextRenderingMode="ClearType"
        FontFamily="Segoe UI Variable Text, Segoe UI, Tahoma" FontSize="13"
        Background="{DynamicResource Bg.App}" Foreground="{DynamicResource Text.Primary}">

  <Window.Resources>
    <ResourceDictionary>
      <ResourceDictionary.MergedDictionaries>
        <ResourceDictionary/>
      </ResourceDictionary.MergedDictionaries>

      <!-- Type ramp -->
      <Style x:Key="Text.Title" TargetType="TextBlock">
        <Setter Property="FontSize" Value="20"/><Setter Property="FontWeight" Value="SemiBold"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
      </Style>
      <Style x:Key="Text.Subtitle" TargetType="TextBlock">
        <Setter Property="FontSize" Value="15"/><Setter Property="FontWeight" Value="SemiBold"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
      </Style>
      <Style x:Key="Text.Body" TargetType="TextBlock">
        <Setter Property="FontSize" Value="13"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
      </Style>
      <Style x:Key="Text.Caption" TargetType="TextBlock">
        <Setter Property="FontSize" Value="12"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Secondary}"/>
      </Style>
      <Style x:Key="Text.Label" TargetType="TextBlock">
        <Setter Property="FontSize" Value="12"/><Setter Property="FontWeight" Value="SemiBold"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Secondary}"/>
        <Setter Property="Margin" Value="0,0,0,4"/>
      </Style>

      <!-- Focus ring -->
      <Style x:Key="FocusRing">
        <Setter Property="Control.FocusVisualStyle">
          <Setter.Value>
            <Style>
              <Setter Property="Control.Template">
                <Setter.Value>
                  <ControlTemplate>
                    <Rectangle Margin="-2" StrokeThickness="2" RadiusX="5" RadiusY="5"
                               Stroke="{DynamicResource Text.Primary}" SnapsToDevicePixels="True"/>
                  </ControlTemplate>
                </Setter.Value>
              </Setter>
            </Style>
          </Setter.Value>
        </Setter>
      </Style>

      <!-- Buttons -->
      <Style x:Key="Btn.Base" TargetType="Button" BasedOn="{StaticResource FocusRing}">
        <Setter Property="Padding" Value="16,7"/>
        <Setter Property="MinHeight" Value="32"/>
        <Setter Property="FontSize" Value="13"/>
        <Setter Property="Cursor" Value="Hand"/>
        <Setter Property="HorizontalContentAlignment" Value="Center"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="Button">
              <Border x:Name="Bd" CornerRadius="4" Background="{TemplateBinding Background}"
                      BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1"
                      SnapsToDevicePixels="True">
                <ContentPresenter Margin="{TemplateBinding Padding}"
                                  HorizontalAlignment="Center" VerticalAlignment="Center"
                                  RecognizesAccessKey="True"/>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                  <Setter TargetName="Bd" Property="Opacity" Value="0.90"/>
                </Trigger>
                <Trigger Property="IsPressed" Value="True">
                  <Setter TargetName="Bd" Property="Opacity" Value="0.78"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                  <Setter TargetName="Bd" Property="Opacity" Value="0.40"/>
                  <Setter Property="Cursor" Value="Arrow"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>

      <Style x:Key="Btn.Primary" TargetType="Button" BasedOn="{StaticResource Btn.Base}">
        <Setter Property="Background" Value="{DynamicResource Accent.Default}"/>
        <Setter Property="BorderBrush" Value="{DynamicResource Accent.Default}"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.OnAccent}"/>
        <Setter Property="FontWeight" Value="SemiBold"/>
      </Style>
      <Style x:Key="Btn.Secondary" TargetType="Button" BasedOn="{StaticResource Btn.Base}">
        <Setter Property="Background" Value="{DynamicResource Bg.Control}"/>
        <Setter Property="BorderBrush" Value="{DynamicResource Stroke.Control}"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
      </Style>
      <Style x:Key="Btn.Subtle" TargetType="Button" BasedOn="{StaticResource Btn.Base}">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="BorderBrush" Value="Transparent"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="Padding" Value="10,6"/>
      </Style>
      <Style x:Key="Btn.Danger" TargetType="Button" BasedOn="{StaticResource Btn.Base}">
        <Setter Property="Background" Value="{DynamicResource State.Danger}"/>
        <Setter Property="BorderBrush" Value="{DynamicResource State.Danger}"/>
        <Setter Property="Foreground" Value="#FFFFFF"/>
        <Setter Property="FontWeight" Value="SemiBold"/>
      </Style>

      <!-- TextBox -->
      <Style TargetType="TextBox" BasedOn="{StaticResource FocusRing}">
        <Setter Property="Background" Value="{DynamicResource Bg.Control}"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="BorderBrush" Value="{DynamicResource Stroke.Control}"/>
        <Setter Property="BorderThickness" Value="1"/>
        <Setter Property="Padding" Value="9,6"/>
        <Setter Property="MinHeight" Value="32"/>
        <Setter Property="VerticalContentAlignment" Value="Center"/>
        <Setter Property="CaretBrush" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="SelectionBrush" Value="{DynamicResource Accent.Default}"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="TextBox">
              <Border x:Name="Bd" CornerRadius="4" Background="{TemplateBinding Background}"
                      BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}"
                      SnapsToDevicePixels="True">
                <Grid>
                  <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"
                                VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
                  <Border x:Name="Underline" Height="2" VerticalAlignment="Bottom" CornerRadius="0,0,4,4"
                          Background="{DynamicResource Accent.Default}" Visibility="Collapsed"/>
                </Grid>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                  <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Stroke.Strong}"/>
                </Trigger>
                <Trigger Property="IsKeyboardFocusWithin" Value="True">
                  <Setter TargetName="Underline" Property="Visibility" Value="Visible"/>
                  <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Stroke.Strong}"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                  <Setter TargetName="Bd" Property="Opacity" Value="0.5"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>

      <Style x:Key="Editor" TargetType="TextBox" BasedOn="{StaticResource {x:Type TextBox}}">
        <Setter Property="FontFamily" Value="Cascadia Mono, Consolas, Courier New"/>
        <Setter Property="FontSize" Value="12.5"/>
        <Setter Property="Background" Value="{DynamicResource Editor.Bg}"/>
        <Setter Property="AcceptsReturn" Value="True"/>
        <Setter Property="AcceptsTab" Value="True"/>
        <Setter Property="TextWrapping" Value="NoWrap"/>
        <Setter Property="VerticalContentAlignment" Value="Top"/>
        <Setter Property="VerticalScrollBarVisibility" Value="Auto"/>
        <Setter Property="HorizontalScrollBarVisibility" Value="Auto"/>
      </Style>

      <!-- ComboBox: fully templated so it themes correctly in dark mode -->
      <Style x:Key="ComboToggle" TargetType="ToggleButton">
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="ToggleButton">
              <Border x:Name="Bd" CornerRadius="4" Background="{DynamicResource Bg.Control}"
                      BorderBrush="{DynamicResource Stroke.Control}" BorderThickness="1" SnapsToDevicePixels="True">
                <Path x:Name="Arrow" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,10,0"
                      Data="M 0 0 L 4.5 4.5 L 9 0" Stroke="{DynamicResource Text.Secondary}" StrokeThickness="1.5"/>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                  <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Bg.ControlHover}"/>
                  <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Stroke.Strong}"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                  <Setter TargetName="Bd" Property="Opacity" Value="0.45"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>

      <Style TargetType="ComboBox" BasedOn="{StaticResource FocusRing}">
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="MinHeight" Value="32"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="ComboBox">
              <Grid>
                <ToggleButton Style="{StaticResource ComboToggle}" Focusable="False" ClickMode="Press"
                              IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"/>
                <ContentPresenter x:Name="ContentSite" IsHitTestVisible="False" Margin="10,0,28,0"
                                  Content="{TemplateBinding SelectionBoxItem}"
                                  ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                  VerticalAlignment="Center" HorizontalAlignment="Left"/>
                <TextBox x:Name="PART_EditableTextBox" Visibility="Collapsed" Margin="6,1,26,1"
                         Background="Transparent" BorderThickness="0" MinHeight="0" Padding="4,0"
                         Foreground="{DynamicResource Text.Primary}" VerticalContentAlignment="Center"/>
                <Popup x:Name="PART_Popup" AllowsTransparency="True" Placement="Bottom" Focusable="False"
                       IsOpen="{TemplateBinding IsDropDownOpen}">
                  <Border MinWidth="{TemplateBinding ActualWidth}" MaxHeight="280" Margin="0,3,0,0"
                          Background="{DynamicResource Bg.Layer}" BorderBrush="{DynamicResource Stroke.Default}"
                          BorderThickness="1" CornerRadius="5" SnapsToDevicePixels="True">
                    <ScrollViewer>
                      <StackPanel IsItemsHost="True" Margin="0,3" KeyboardNavigation.DirectionalNavigation="Contained"/>
                    </ScrollViewer>
                  </Border>
                </Popup>
              </Grid>
              <ControlTemplate.Triggers>
                <Trigger Property="IsEditable" Value="True">
                  <Setter TargetName="PART_EditableTextBox" Property="Visibility" Value="Visible"/>
                  <Setter TargetName="ContentSite" Property="Visibility" Value="Collapsed"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>

      <Style TargetType="ComboBoxItem">
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="Padding" Value="10,7"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="ComboBoxItem">
              <Border x:Name="Bd" Background="Transparent" CornerRadius="3" Margin="4,1"
                      Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
                <ContentPresenter/>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsHighlighted" Value="True">
                  <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Bg.ControlHover}"/>
                </Trigger>
                <Trigger Property="IsSelected" Value="True">
                  <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Bg.Selected}"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>

      <!-- ScrollBar -->
      <Style x:Key="ScrollThumb" TargetType="Thumb">
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="Thumb">
              <Border Background="{DynamicResource Stroke.Strong}" CornerRadius="3" Margin="3" Opacity="0.6"/>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>
      <Style TargetType="ScrollBar">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="Width" Value="12"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="ScrollBar">
              <Grid Background="Transparent">
                <Track x:Name="PART_Track" IsDirectionReversed="True" ViewportSize="{TemplateBinding ViewportSize}">
                  <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}"/></Track.Thumb>
                  <Track.IncreaseRepeatButton>
                    <RepeatButton Command="ScrollBar.PageDownCommand" Opacity="0" Focusable="False" IsTabStop="False"/>
                  </Track.IncreaseRepeatButton>
                  <Track.DecreaseRepeatButton>
                    <RepeatButton Command="ScrollBar.PageUpCommand" Opacity="0" Focusable="False" IsTabStop="False"/>
                  </Track.DecreaseRepeatButton>
                </Track>
              </Grid>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
        <Style.Triggers>
          <Trigger Property="Orientation" Value="Horizontal">
            <Setter Property="Width" Value="Auto"/>
            <Setter Property="Height" Value="12"/>
            <Setter Property="Template">
              <Setter.Value>
                <ControlTemplate TargetType="ScrollBar">
                  <Grid Background="Transparent">
                    <Track x:Name="PART_Track" ViewportSize="{TemplateBinding ViewportSize}">
                      <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}"/></Track.Thumb>
                      <Track.IncreaseRepeatButton>
                        <RepeatButton Command="ScrollBar.PageRightCommand" Opacity="0" Focusable="False" IsTabStop="False"/>
                      </Track.IncreaseRepeatButton>
                      <Track.DecreaseRepeatButton>
                        <RepeatButton Command="ScrollBar.PageLeftCommand" Opacity="0" Focusable="False" IsTabStop="False"/>
                      </Track.DecreaseRepeatButton>
                    </Track>
                  </Grid>
                </ControlTemplate>
              </Setter.Value>
            </Setter>
          </Trigger>
        </Style.Triggers>
      </Style>

      <!-- CheckBox -->
      <Style TargetType="CheckBox" BasedOn="{StaticResource FocusRing}">
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="Margin" Value="0,5"/>
        <Setter Property="VerticalContentAlignment" Value="Center"/>
      </Style>
      <Style TargetType="RadioButton" BasedOn="{StaticResource FocusRing}">
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="Margin" Value="0,4,18,4"/>
        <Setter Property="VerticalContentAlignment" Value="Center"/>
      </Style>

      <!-- Card -->
      <Style x:Key="Card" TargetType="Border">
        <Setter Property="Background" Value="{DynamicResource Bg.Layer}"/>
        <Setter Property="BorderBrush" Value="{DynamicResource Stroke.Default}"/>
        <Setter Property="BorderThickness" Value="1"/>
        <Setter Property="CornerRadius" Value="6"/>
        <Setter Property="Padding" Value="16"/>
      </Style>

      <!-- Help expander. The stock Expander template draws a circled arrow that does not
           match anything else here, so header and body are both retemplated. -->
      <Style x:Key="Help.ExpanderToggle" TargetType="ToggleButton" BasedOn="{StaticResource FocusRing}">
        <Setter Property="Cursor" Value="Hand"/>
        <Setter Property="FontSize" Value="13"/>
        <Setter Property="FontWeight" Value="SemiBold"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="HorizontalContentAlignment" Value="Left"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="ToggleButton">
              <Border x:Name="Bd" Background="Transparent" CornerRadius="5" Padding="13,10" SnapsToDevicePixels="True">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <ContentPresenter Grid.Column="0" VerticalAlignment="Center" RecognizesAccessKey="True"/>
                  <Path x:Name="Chevron" Grid.Column="1" Width="11" Height="7" Margin="12,0,2,0" Stretch="None"
                        Data="M 1,1 L 5.5,5.5 L 10,1" StrokeThickness="1.5"
                        Stroke="{DynamicResource Text.Tertiary}"
                        VerticalAlignment="Center" RenderTransformOrigin="0.5,0.5">
                    <Path.RenderTransform>
                      <RotateTransform Angle="0"/>
                    </Path.RenderTransform>
                  </Path>
                </Grid>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                  <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Bg.ControlHover}"/>
                  <Setter TargetName="Chevron" Property="Stroke" Value="{DynamicResource Accent.Default}"/>
                </Trigger>
                <Trigger Property="IsChecked" Value="True">
                  <Setter TargetName="Chevron" Property="Stroke" Value="{DynamicResource Accent.Default}"/>
                  <Setter TargetName="Chevron" Property="RenderTransform">
                    <Setter.Value>
                      <RotateTransform Angle="180"/>
                    </Setter.Value>
                  </Setter>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>

      <Style x:Key="Help.Expander" TargetType="Expander">
        <Setter Property="Margin" Value="0,0,0,6"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="Expander">
              <Border x:Name="Shell" CornerRadius="5" SnapsToDevicePixels="True"
                      Background="{DynamicResource Bg.Layer}"
                      BorderBrush="{DynamicResource Stroke.Default}" BorderThickness="1">
                <StackPanel>
                  <ToggleButton x:Name="Head" Style="{StaticResource Help.ExpanderToggle}"
                                Content="{TemplateBinding Header}"
                                IsChecked="{Binding IsExpanded, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"/>
                  <Border x:Name="Body" Visibility="Collapsed" Padding="13,1,13,12">
                    <ContentPresenter/>
                  </Border>
                </StackPanel>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsExpanded" Value="True">
                  <Setter TargetName="Body" Property="Visibility" Value="Visible"/>
                  <Setter TargetName="Shell" Property="Background" Value="{DynamicResource Bg.LayerAlt}"/>
                  <Setter TargetName="Shell" Property="BorderBrush" Value="{DynamicResource Stroke.Control}"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>

      <!-- A docked bullet gives the wrapped continuation lines a true hanging indent. -->
      <Style x:Key="Help.Row" TargetType="DockPanel">
        <Setter Property="Margin" Value="2,0,0,7"/>
      </Style>
      <Style x:Key="Help.Dot" TargetType="TextBlock" BasedOn="{StaticResource Text.Caption}">
        <Setter Property="FontSize" Value="12.5"/>
        <Setter Property="Margin" Value="0,0,8,0"/>
        <Setter Property="VerticalAlignment" Value="Top"/>
      </Style>
      <Style x:Key="Help.Text" TargetType="TextBlock" BasedOn="{StaticResource Text.Caption}">
        <Setter Property="FontSize" Value="12.5"/>
        <Setter Property="TextWrapping" Value="Wrap"/>
      </Style>

      <!-- TabControl -->
      <Style TargetType="TabControl">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="BorderThickness" Value="0"/>
        <Setter Property="Padding" Value="0,10,0,0"/>
      </Style>
      <Style TargetType="TabItem">
        <Setter Property="Foreground" Value="{DynamicResource Text.Secondary}"/>
        <Setter Property="FontSize" Value="13"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="TabItem">
              <Border x:Name="Bd" Background="Transparent" Padding="14,8" Margin="0,0,4,0" CornerRadius="4,4,0,0">
                <Grid>
                  <ContentPresenter ContentSource="Header" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                  <Border x:Name="Ind" Height="2.5" VerticalAlignment="Bottom" Margin="4,0" CornerRadius="2"
                          Background="{DynamicResource Accent.Default}" Visibility="Collapsed"/>
                </Grid>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsSelected" Value="True">
                  <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
                  <Setter Property="FontWeight" Value="SemiBold"/>
                  <Setter TargetName="Ind" Property="Visibility" Value="Visible"/>
                </Trigger>
                <MultiTrigger>
                  <MultiTrigger.Conditions>
                    <Condition Property="IsSelected" Value="False"/>
                    <Condition Property="IsMouseOver" Value="True"/>
                  </MultiTrigger.Conditions>
                  <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Bg.ControlHover}"/>
                </MultiTrigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>

      <!-- TreeView -->
      <Style TargetType="TreeView">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="BorderThickness" Value="0"/>
      </Style>
      <Style TargetType="TreeViewItem" BasedOn="{StaticResource FocusRing}">
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="Padding" Value="3,4"/>
        <Setter Property="Margin" Value="0,1"/>
      </Style>

      <!-- One depth-agnostic template: ItemsSource with no ItemTemplate recurses to
           every level, so namespace, resourceType and operation rows all use this. -->
      <HierarchicalDataTemplate x:Key="Catalog.Node" ItemsSource="{Binding Children, Mode=OneTime}">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Border x:Name="Chip" Grid.Column="0" CornerRadius="3" Padding="5,1" MinWidth="46"
                  Margin="0,0,7,0" VerticalAlignment="Center"
                  Background="{Binding MethodBrush, Mode=OneTime}">
            <TextBlock Text="{Binding Method, Mode=OneTime}" Foreground="White" FontSize="10"
                       FontWeight="Bold" HorizontalAlignment="Center"/>
          </Border>
          <TextBlock x:Name="RowLabel" Grid.Column="1" Text="{Binding Label, Mode=OneTime}"
                     VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
          <TextBlock x:Name="RowCount" Grid.Column="2" Text="{Binding CountText, Mode=OneTime}"
                     VerticalAlignment="Center" Margin="8,0,0,0" Opacity="0.6" Visibility="Collapsed"/>
        </Grid>
        <HierarchicalDataTemplate.Triggers>
          <DataTrigger Binding="{Binding Method}" Value="">
            <Setter TargetName="Chip" Property="Visibility" Value="Collapsed"/>
          </DataTrigger>
          <DataTrigger Binding="{Binding IsGroup}" Value="True">
            <Setter TargetName="RowLabel" Property="FontWeight" Value="SemiBold"/>
            <Setter TargetName="RowCount" Property="Visibility" Value="Visible"/>
          </DataTrigger>
        </HierarchicalDataTemplate.Triggers>
      </HierarchicalDataTemplate>

      <!-- BasedOn is mandatory: an ItemContainerStyle outranks the implicit TreeViewItem
           style, so without it every row loses Foreground, Padding and the focus ring. -->
      <Style x:Key="Catalog.NodeContainer" TargetType="TreeViewItem" BasedOn="{StaticResource {x:Type TreeViewItem}}">
        <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
        <Setter Property="IsExpanded" Value="{Binding IsExpanded, Mode=TwoWay}"/>
        <Setter Property="ToolTip" Value="{Binding Tip}"/>
        <Setter Property="AutomationProperties.Name" Value="{Binding AutomationName}"/>
      </Style>

      <Style TargetType="ProgressBar">
        <Setter Property="Height" Value="2.5"/>
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="BorderThickness" Value="0"/>
        <Setter Property="Foreground" Value="{DynamicResource Accent.Default}"/>
      </Style>

      <!-- Without these the OS theme supplies black item text, which disappears on the dark palette. -->
      <Style TargetType="ListBox">
        <Setter Property="Background" Value="{DynamicResource Bg.Control}"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="BorderBrush" Value="{DynamicResource Stroke.Control}"/>
        <Setter Property="BorderThickness" Value="1"/>
        <Setter Property="Padding" Value="3"/>
      </Style>

      <Style TargetType="ListBoxItem">
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="Padding" Value="9,6"/>
        <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
        <Setter Property="SnapsToDevicePixels" Value="True"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="ListBoxItem">
              <Border x:Name="Row" CornerRadius="4" Margin="0,1" SnapsToDevicePixels="True"
                      Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
                <ContentPresenter VerticalAlignment="Center"
                                  HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"/>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                  <Setter TargetName="Row" Property="Background" Value="{DynamicResource Bg.ControlHover}"/>
                </Trigger>
                <Trigger Property="IsSelected" Value="True">
                  <Setter TargetName="Row" Property="Background" Value="{DynamicResource Bg.Selected}"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                  <Setter Property="Foreground" Value="{DynamicResource Text.Tertiary}"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>

      <Style TargetType="GridSplitter">
        <Setter Property="Background" Value="{DynamicResource Stroke.Default}"/>
      </Style>
      <Style TargetType="Separator">
        <Setter Property="Background" Value="{DynamicResource Stroke.Default}"/>
        <Setter Property="Margin" Value="0,8"/>
      </Style>
      <Style TargetType="ToolTip">
        <Setter Property="Background" Value="{DynamicResource Bg.Layer}"/>
        <Setter Property="Foreground" Value="{DynamicResource Text.Primary}"/>
        <Setter Property="BorderBrush" Value="{DynamicResource Stroke.Default}"/>
        <Setter Property="Padding" Value="10,6"/>
        <Setter Property="MaxWidth" Value="420"/>
        <!-- The default presenter renders a string in a non-wrapping TextBlock, so
             MaxWidth clips it mid-word instead of wrapping onto a second line. -->
        <Setter Property="ContentTemplate">
          <Setter.Value>
            <DataTemplate>
              <TextBlock Text="{Binding}" TextWrapping="Wrap"/>
            </DataTemplate>
          </Setter.Value>
        </Setter>
      </Style>
    </ResourceDictionary>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>   <!-- command bar -->
      <RowDefinition Height="Auto"/>   <!-- context banner -->
      <RowDefinition Height="Auto"/>   <!-- progress -->
      <RowDefinition Height="*"/>      <!-- body -->
      <RowDefinition Height="Auto"/>   <!-- status bar -->
    </Grid.RowDefinitions>

    <!-- ============ Command bar ============ -->
    <Border Grid.Row="0" Background="{DynamicResource Bg.Layer}" BorderBrush="{DynamicResource Stroke.Default}" BorderThickness="0,0,0,1">
      <Grid Margin="18,11">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>

        <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
          <Grid Width="44" Height="44">
            <Border x:Name="BorderLogoFallback" CornerRadius="8" Background="{DynamicResource Accent.Default}">
              <TextBlock Text="AR" Foreground="{DynamicResource Text.OnAccent}" FontWeight="Bold" FontSize="17"
                         HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <Image x:Name="ImgLogo" Visibility="Collapsed" Stretch="Uniform"
                   RenderOptions.BitmapScalingMode="HighQuality"
                   AutomationProperties.Name="ArmClient-PS logo"/>
          </Grid>
          <StackPanel Margin="13,0,0,0" VerticalAlignment="Center">
            <TextBlock Text="ArmClient-PS" Style="{StaticResource Text.Subtitle}"/>
            <TextBlock x:Name="TxtVersion" Text="Azure Resource Manager console"
                       Style="{StaticResource Text.Caption}" FontSize="11.5"/>
          </StackPanel>
        </StackPanel>

        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
          <TextBlock Text="Cloud" Style="{StaticResource Text.Caption}" VerticalAlignment="Center" Margin="0,0,7,0"/>
          <ComboBox x:Name="CmbEnvironment" Width="182" ToolTip="Azure environment used for sign-in and ARM endpoints"/>
          <Button x:Name="BtnSignIn" Content="_Sign in" Style="{StaticResource Btn.Primary}" Margin="10,0,0,0"/>
          <Button x:Name="BtnSignOut" Content="Sign out" Style="{StaticResource Btn.Secondary}" Margin="7,0,0,0" IsEnabled="False"/>
          <Button x:Name="BtnTenant" Content="_Tenant" Style="{StaticResource Btn.Subtle}" Margin="7,0,0,0" IsEnabled="False"
                  ToolTip="Switch the Azure tenant this session is signed in to"/>
          <Button x:Name="BtnDefaults" Content="_Defaults" Style="{StaticResource Btn.Subtle}" Margin="7,0,0,0"
                  ToolTip="Set values that pre-fill operation parameters, such as subscription and resource group"/>
          <Button x:Name="BtnGuide" Content="Guide" Style="{StaticResource Btn.Subtle}" Margin="7,0,0,0"
                  ToolTip="Show the getting started guide"/>
          <Button x:Name="BtnTheme" Content="Theme" Style="{StaticResource Btn.Subtle}" Margin="7,0,0,0" ToolTip="Toggle light and dark theme"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- ============ Context banner ============ -->
    <Border x:Name="BorderContext" Grid.Row="1" Padding="16,8" BorderThickness="0,0,0,1"
            Background="{DynamicResource State.NeutralBg}" BorderBrush="{DynamicResource Stroke.Default}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Border x:Name="BorderEnvChip" Grid.Column="0" CornerRadius="4" Padding="8,3" VerticalAlignment="Center"
                Background="{DynamicResource State.Neutral}">
          <TextBlock x:Name="TxtEnvChip" Text="NOT SIGNED IN" Foreground="White" FontWeight="SemiBold" FontSize="11"/>
        </Border>
        <!-- Directly in the star column, not inside a StackPanel: a horizontal StackPanel
             measures its children with infinite width, so TextTrimming never engages and
             the text overruns the integrity label instead of ellipsing. -->
        <TextBlock x:Name="TxtContext" Grid.Column="1" Margin="14,0,14,0" VerticalAlignment="Center"
                   Style="{StaticResource Text.Body}" FontSize="12.5"
                   Text="Sign in to select a tenant and subscription." TextTrimming="CharacterEllipsis"/>
        <TextBlock x:Name="TxtIntegrity" Grid.Column="2" Style="{StaticResource Text.Caption}"
                   VerticalAlignment="Center" FontSize="11.5"/>
      </Grid>
    </Border>

    <ProgressBar x:Name="PrgBusy" Grid.Row="2" IsIndeterminate="True" Visibility="Collapsed"/>

    <!-- ============ Body ============ -->
    <Grid Grid.Row="3" Margin="0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="350" MinWidth="240"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*" MinWidth="520"/>
      </Grid.ColumnDefinitions>

      <!-- Catalog rail -->
      <Border Grid.Column="0" Background="{DynamicResource Bg.LayerAlt}" BorderBrush="{DynamicResource Stroke.Default}" BorderThickness="0,0,1,0">
        <Grid Margin="12">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <Grid Grid.Row="0" Margin="2,0,0,6">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBlock Grid.Column="0" Text="Operations" Style="{StaticResource Text.Label}" VerticalAlignment="Center"/>
            <Button Grid.Column="1" x:Name="BtnDiscover" Content="Discover all" Style="{StaticResource Btn.Subtle}"
                    FontSize="11.5" Padding="8,3" IsEnabled="False"
                    ToolTip="Query Azure for every resource provider operation available to this subscription"/>
          </Grid>
          <Grid Grid.Row="1" Margin="0,0,0,6">
            <TextBox x:Name="TxtSearch" ToolTip="Filter operations by name, alias, category, or description"/>
            <!-- 10px = 1px border + 9px padding, so the hint sits exactly where the caret does. -->
            <TextBlock x:Name="TxtSearchHint" Text="Search operations" IsHitTestVisible="False"
                       Margin="10,0,0,0" VerticalAlignment="Center" FontSize="13"
                       Foreground="{DynamicResource Text.Tertiary}"/>
          </Grid>
          <CheckBox Grid.Row="2" x:Name="ChkDeployedOnly" Margin="2,0,0,6" IsEnabled="False"
                    Content="Only what I have deployed"
                    ToolTip="Hide operations for resource types that do not exist in this subscription"/>
          <TextBlock Grid.Row="3" x:Name="TxtCatalogStatus" Style="{StaticResource Text.Caption}"
                     FontSize="11" TextWrapping="Wrap" Margin="2,0,4,12"
                     Text="28 verified presets. Sign in to discover every ARM operation."/>
          <TreeView Grid.Row="4" x:Name="TreeCatalog" BorderThickness="0"
                    ScrollViewer.HorizontalScrollBarVisibility="Disabled"
                    ScrollViewer.VerticalScrollBarVisibility="Auto"
                    ScrollViewer.CanContentScroll="True"
                    VirtualizingStackPanel.IsVirtualizing="True"
                    VirtualizingStackPanel.VirtualizationMode="Recycling"
                    ItemTemplate="{StaticResource Catalog.Node}"
                    ItemContainerStyle="{StaticResource Catalog.NodeContainer}">
            <!-- One shared menu, not one per item: 18,000 nodes cannot each own a ContextMenu. -->
            <TreeView.ContextMenu>
              <ContextMenu x:Name="MenuCatalog">
                <MenuItem x:Name="MenuDocs" Header="_View documentation"/>
                <MenuItem x:Name="MenuCopyDocs" Header="_Copy documentation link"/>
              </ContextMenu>
            </TreeView.ContextMenu>
          </TreeView>
        </Grid>
      </Border>

      <GridSplitter Grid.Column="1" Width="1" HorizontalAlignment="Stretch" VerticalAlignment="Stretch"/>

      <!-- Request + response -->
      <Grid Grid.Column="2">
        <Grid.RowDefinitions>
          <RowDefinition Height="2*" MinHeight="260"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="1*" MinHeight="150"/>
        </Grid.RowDefinitions>

        <!-- The scroll area and the pinned action bar move together as one pane, so the
             splitter below has a star-sized row on both sides and resizes cleanly. -->
        <Grid Grid.Row="0">
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

        <ScrollViewer x:Name="ScrollRequest" Grid.Row="0" VerticalScrollBarVisibility="Auto" Padding="18,16,18,10">
          <StackPanel>

            <!-- Getting started. Shown on launch, hidden the moment an operation is opened. -->
            <Border x:Name="PanelWelcome" Style="{StaticResource Card}" Margin="0,0,0,12" Padding="18">
              <StackPanel>
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <StackPanel Grid.Column="0">
                    <TextBlock Text="Getting started" Style="{StaticResource Text.Title}"/>
                    <TextBlock Style="{StaticResource Text.Caption}" TextWrapping="Wrap" Margin="0,5,12,0"
                               Text="This is a console for the Azure Resource Manager REST API. Pick an operation on the left, fill in the blanks, and send it. Open a section below to learn how."/>
                  </StackPanel>
                  <Button x:Name="BtnWelcomeClose" Grid.Column="1" Content="Dismiss" VerticalAlignment="Top"
                          Style="{StaticResource Btn.Subtle}" FontSize="11.5" Padding="10,4" MinHeight="0"
                          ToolTip="Hide this guide. Select Guide in the toolbar to bring it back."/>
                </Grid>

                <Grid Margin="0,16,0,10">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <Border Grid.Column="0" Background="{DynamicResource Bg.Subtle}" CornerRadius="5" Padding="11,10" Margin="0,0,8,0">
                    <StackPanel Orientation="Horizontal">
                      <Border Width="21" Height="21" CornerRadius="11" VerticalAlignment="Top"
                              Background="{DynamicResource Accent.Default}">
                        <TextBlock Text="1" FontSize="11" FontWeight="Bold" Foreground="{DynamicResource Text.OnAccent}"
                                   HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Border>
                      <StackPanel Margin="9,0,0,0">
                        <TextBlock Text="Sign in" Style="{StaticResource Text.Body}" FontSize="12.5" FontWeight="SemiBold"/>
                        <TextBlock Text="Pick a cloud, then Sign in" Style="{StaticResource Text.Caption}"
                                   FontSize="11" TextWrapping="Wrap" Margin="0,2,0,0"/>
                      </StackPanel>
                    </StackPanel>
                  </Border>
                  <Border Grid.Column="1" Background="{DynamicResource Bg.Subtle}" CornerRadius="5" Padding="11,10" Margin="0,0,8,0">
                    <StackPanel Orientation="Horizontal">
                      <Border Width="21" Height="21" CornerRadius="11" VerticalAlignment="Top"
                              Background="{DynamicResource Accent.Default}">
                        <TextBlock Text="2" FontSize="11" FontWeight="Bold" Foreground="{DynamicResource Text.OnAccent}"
                                   HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Border>
                      <StackPanel Margin="9,0,0,0">
                        <TextBlock Text="Choose" Style="{StaticResource Text.Body}" FontSize="12.5" FontWeight="SemiBold"/>
                        <TextBlock Text="Search the operations list" Style="{StaticResource Text.Caption}"
                                   FontSize="11" TextWrapping="Wrap" Margin="0,2,0,0"/>
                      </StackPanel>
                    </StackPanel>
                  </Border>
                  <Border Grid.Column="2" Background="{DynamicResource Bg.Subtle}" CornerRadius="5" Padding="11,10">
                    <StackPanel Orientation="Horizontal">
                      <Border Width="21" Height="21" CornerRadius="11" VerticalAlignment="Top"
                              Background="{DynamicResource Accent.Default}">
                        <TextBlock Text="3" FontSize="11" FontWeight="Bold" Foreground="{DynamicResource Text.OnAccent}"
                                   HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Border>
                      <StackPanel Margin="9,0,0,0">
                        <TextBlock Text="Send" Style="{StaticResource Text.Body}" FontSize="12.5" FontWeight="SemiBold"/>
                        <TextBlock Text="Review the response below" Style="{StaticResource Text.Caption}"
                                   FontSize="11" TextWrapping="Wrap" Margin="0,2,0,0"/>
                      </StackPanel>
                    </StackPanel>
                  </Border>
                </Grid>

                <Expander x:Name="ExpGuideSignIn" Style="{StaticResource Help.Expander}" IsExpanded="True"
                          Header="1.  Sign in and pick your cloud">
                  <StackPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Choose your cloud in the Cloud list at the top right. AzureCloud is the public cloud; the other entries cover the sovereign clouds."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Select Sign in. A browser window opens so Azure can authenticate you. The tool never sees your password."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="The banner under the toolbar then shows the tenant and subscription every request will use."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Have access to more than one tenant? Select Tenant to switch. Anything discovered for the previous tenant is cleared, so nothing stale carries over."/>
                    </DockPanel>
                  </StackPanel>
                </Expander>

                <Expander x:Name="ExpGuideFind" Style="{StaticResource Help.Expander}"
                          Header="2.  Find the operation you need">
                  <StackPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="The Operations list on the left opens with a set of verified presets, grouped by service."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Type in the Search operations box to filter by name, alias, category, or description."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Need something that is not a preset? After signing in, select Discover all to pull every operation your subscription exposes. That adds thousands of entries, so searching is far quicker than scrolling."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Tick Only what I have deployed to hide resource types you do not actually have in the current subscription."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Right-click any operation for View documentation or Copy documentation link, which open the reference page for that exact call."/>
                    </DockPanel>
                  </StackPanel>
                </Expander>

                <Expander x:Name="ExpGuideFill" Style="{StaticResource Help.Expander}"
                          Header="3.  Fill in the parameters">
                  <StackPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Selecting an operation replaces this guide with its details: what it does, the ARM path it calls, and one box per parameter."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Parameters that can be looked up become lists instead of empty boxes. Pick a subscription and the resource group list fills itself; pick a resource group and the resource list follows."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Request mode picks how the URL is built. Leave it on Operation preset for guided requests, switch to Relative path to type an ARM path yourself, or Absolute URI to call a full address."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Method and API version come from the preset. Tick the override boxes only when you deliberately need a different one."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="The Body, Headers, and Options tabs hold the request body, any extra headers, and settings such as long-running operation polling and raw output."/>
                    </DockPanel>
                  </StackPanel>
                </Expander>

                <Expander x:Name="ExpGuideSend" Style="{StaticResource Help.Expander}"
                          Header="4.  Send it and read the result">
                  <StackPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Select Send request. The line above the buttons tells you first if anything is still missing."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="The status code and elapsed time appear above the response pane at the bottom, with the body on the Response tab and the returned headers next to it."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Secrets and keys are redacted before anything is displayed. Reveal raw shows the untouched response when you genuinely need it."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Copy as CLI hands you the equivalent command line, which is the easiest way to move a call you built here into a script or a change record."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="The Activity log tab keeps a record of the session, and Save writes the response to a file."/>
                    </DockPanel>
                  </StackPanel>
                </Expander>

                <Expander x:Name="ExpGuideDefaults" Style="{StaticResource Help.Expander}"
                          Header="5.  Stop retyping the same values">
                  <StackPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Select Defaults in the toolbar to store a subscription, a resource group, or any other parameter value once."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="From then on, every operation you open arrives with those boxes already filled in."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Saved defaults are encrypted for your Windows account, so another account cannot read the file. Export them unencrypted only when you mean to share them."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Defaults are checked against the tenant you are signed in to, so a subscription left over from somewhere else is flagged rather than used silently."/>
                    </DockPanel>
                  </StackPanel>
                </Expander>

                <Expander x:Name="ExpGuideShortcuts" Style="{StaticResource Help.Expander}"
                          Header="Keyboard and mouse">
                  <StackPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Alt+S signs in, Alt+T switches tenant, Alt+D opens defaults, Alt+R sends the request."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Alt+O, Alt+P, and Alt+U switch between operation preset, relative path, and absolute URI."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Tab moves through the parameter boxes in order, so a request can be filled in without touching the mouse."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Drag the divider beside the operations list, or the one above the response, to give a pane more room."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Theme switches between light and dark."/>
                    </DockPanel>
                  </StackPanel>
                </Expander>

                <Expander x:Name="ExpGuideSafety" Style="{StaticResource Help.Expander}"
                          Header="What this tool does with your credentials">
                  <StackPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Requests go to the Resource Manager endpoint of the cloud you selected, and your access token goes with them. Nothing is sent anywhere else."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="That token is never written to the response pane, the activity log, or the copied command line."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Absolute URI mode can reach any address, so a request aimed at any host other than Resource Manager asks you to confirm first."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="Documentation links only ever open learn.microsoft.com, even though the address is built from provider metadata."/>
                    </DockPanel>
                    <DockPanel Style="{StaticResource Help.Row}">
                      <TextBlock DockPanel.Dock="Left" Style="{StaticResource Help.Dot}" Text="&#8226;"/>
                      <TextBlock Style="{StaticResource Help.Text}" Text="This tool sends exactly the request you build. A DELETE or a PUT reaches Azure as written, so read the path before you send one."/>
                    </DockPanel>
                  </StackPanel>
                </Expander>

                <TextBlock Style="{StaticResource Text.Caption}" TextWrapping="Wrap" Margin="2,8,0,0" FontSize="11.5"
                           Text="Pick an operation on the left to begin. This guide closes when you do, and Guide in the toolbar brings it back."/>
              </StackPanel>
            </Border>

            <!-- Mode -->
            <TextBlock Text="Request mode" Style="{StaticResource Text.Label}"/>
            <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
              <RadioButton x:Name="RbPreset" Content="_Operation preset" GroupName="Mode" IsChecked="True"/>
              <RadioButton x:Name="RbPath" Content="Relative _path" GroupName="Mode"/>
              <RadioButton x:Name="RbUri" Content="Absolute _URI" GroupName="Mode"/>
            </StackPanel>

            <!-- Preset panel -->
            <Border x:Name="PanelPreset" Style="{StaticResource Card}" Margin="0,0,0,12">
              <StackPanel>
              <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
                <Border x:Name="BorderProvenance" CornerRadius="3" Padding="6,2" Visibility="Collapsed"
                        Background="{DynamicResource State.Warning}">
                  <TextBlock x:Name="TxtProvenance" Text="DISCOVERED" Foreground="White" FontSize="10" FontWeight="Bold"/>
                </Border>
              </StackPanel>
              <StackPanel Orientation="Horizontal">
                <TextBlock x:Name="TxtPresetName" Text="Select an operation" Style="{StaticResource Text.Subtitle}"
                           VerticalAlignment="Center"/>
                <Button x:Name="BtnDocs" Visibility="Collapsed" Margin="8,0,0,0" VerticalAlignment="Center"
                        Width="18" Height="18" Padding="0" Cursor="Hand"
                        Background="Transparent" BorderThickness="0">
                  <Button.Template>
                    <ControlTemplate TargetType="Button">
                      <Border x:Name="Ring" CornerRadius="9" Width="18" Height="18"
                              BorderThickness="1.2" BorderBrush="{DynamicResource Text.Tertiary}"
                              Background="Transparent" SnapsToDevicePixels="True">
                        <TextBlock x:Name="Mark" Text="?" FontSize="11.5" FontWeight="Bold"
                                   HorizontalAlignment="Center" VerticalAlignment="Center"
                                   Foreground="{DynamicResource Text.Tertiary}"/>
                      </Border>
                      <ControlTemplate.Triggers>
                        <Trigger Property="IsMouseOver" Value="True">
                          <Setter TargetName="Ring" Property="BorderBrush" Value="{DynamicResource Accent.Default}"/>
                          <Setter TargetName="Mark" Property="Foreground" Value="{DynamicResource Accent.Default}"/>
                        </Trigger>
                      </ControlTemplate.Triggers>
                    </ControlTemplate>
                  </Button.Template>
                </Button>
              </StackPanel>
                <TextBlock x:Name="TxtPresetDesc" Text="Choose an operation from the list to build a request."
                           Style="{StaticResource Text.Caption}" TextWrapping="Wrap" Margin="0,3,0,0"/>
                <Border Background="{DynamicResource Bg.Subtle}" CornerRadius="4" Padding="10,7" Margin="0,11,0,0">
                  <TextBlock x:Name="TxtPresetPath" Style="{StaticResource Text.Caption}"
                             FontFamily="Cascadia Mono, Consolas" TextWrapping="Wrap" Text="-"/>
                </Border>
                <StackPanel x:Name="PanelScope" Margin="0,12,0,0" Visibility="Collapsed">
                  <TextBlock Text="Scope" Style="{StaticResource Text.Label}"/>
                  <ComboBox x:Name="CmbScope" HorizontalAlignment="Left" MinWidth="260"/>
                  <TextBlock x:Name="TxtScopeEvidence" Style="{StaticResource Text.Caption}" TextWrapping="Wrap" Margin="0,5,0,0"/>
                </StackPanel>
                <ItemsControl x:Name="PnlPresetParams" Margin="0,12,0,0"/>
                <TextBlock x:Name="TxtPresetNotes" Style="{StaticResource Text.Caption}" TextWrapping="Wrap"
                           Margin="0,10,0,0" Visibility="Collapsed"/>
              </StackPanel>
            </Border>

            <!-- Path panel -->
            <Border x:Name="PanelPath" Style="{StaticResource Card}" Margin="0,0,0,12" Visibility="Collapsed">
              <StackPanel>
                <TextBlock Text="Relative ARM path" Style="{StaticResource Text.Label}"/>
                <TextBox x:Name="TxtRelativePath" FontFamily="Cascadia Mono, Consolas"
                         ToolTip="Example: /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example"/>
                <TextBlock Text="Resolved against the Resource Manager endpoint for the signed-in environment."
                           Style="{StaticResource Text.Caption}" Margin="0,6,0,0"/>
              </StackPanel>
            </Border>

            <!-- URI panel -->
            <Border x:Name="PanelUri" Style="{StaticResource Card}" Margin="0,0,0,12" Visibility="Collapsed">
              <StackPanel>
                <TextBlock Text="Absolute HTTPS URI" Style="{StaticResource Text.Label}"/>
                <TextBox x:Name="TxtUri" FontFamily="Cascadia Mono, Consolas"
                         ToolTip="Must be an absolute HTTPS URI"/>
                <Border Background="{DynamicResource State.WarningBg}" CornerRadius="4" Padding="10,7" Margin="0,9,0,0">
                  <TextBlock Style="{StaticResource Text.Caption}" TextWrapping="Wrap"
                             Text="An Azure Resource Manager access token is attached to this request. Only target hosts you trust. Requests to a host other than Resource Manager require confirmation."/>
                </Border>
              </StackPanel>
            </Border>

            <!-- Method + api-version -->
            <Border Style="{StaticResource Card}" Margin="0,0,0,12">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Margin="0,0,20,0">
                  <TextBlock Text="Method" Style="{StaticResource Text.Label}"/>
                  <StackPanel Orientation="Horizontal">
                    <Border x:Name="BorderMethodChip" CornerRadius="4" Padding="9,5" MinWidth="66" Margin="0,0,8,0"
                            Background="{DynamicResource Accent.Default}" VerticalAlignment="Center">
                      <TextBlock x:Name="TxtMethodChip" Text="GET" Foreground="White" FontWeight="Bold" FontSize="11.5"
                                 HorizontalAlignment="Center"/>
                    </Border>
                    <ComboBox x:Name="CmbMethod" Width="118"/>
                  </StackPanel>
                  <CheckBox x:Name="ChkOverrideMethod" Content="Override preset method" FontSize="11.5"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Margin="0,0,20,0">
                  <TextBlock Text="API version" Style="{StaticResource Text.Label}"/>
                  <ComboBox x:Name="CmbApiVersion" Width="190" IsEditable="True"/>
                  <CheckBox x:Name="ChkOverrideApiVersion" Content="Override preset api-version" FontSize="11.5"/>
                </StackPanel>
                <StackPanel Grid.Column="2" VerticalAlignment="Bottom" HorizontalAlignment="Right">
                  <TextBlock Text="Effective request" Style="{StaticResource Text.Label}" HorizontalAlignment="Right"/>
                  <TextBlock x:Name="TxtEffective" Style="{StaticResource Text.Caption}" HorizontalAlignment="Right"
                             FontFamily="Cascadia Mono, Consolas" TextTrimming="CharacterEllipsis" Text="-"/>
                </StackPanel>
              </Grid>
            </Border>

            <!-- Body / headers / options -->
            <TabControl x:Name="TabRequest">
              <TabItem Header="Body">
                <StackPanel Margin="0,10,0,0">
                  <StackPanel Orientation="Horizontal" Margin="0,0,0,9">
                    <RadioButton x:Name="RbBodyNone" Content="None" GroupName="Body" IsChecked="True"/>
                    <RadioButton x:Name="RbBodyInline" Content="Inline JSON" GroupName="Body"/>
                    <RadioButton x:Name="RbBodyFile" Content="From file" GroupName="Body"/>
                    <Button x:Name="BtnFormatJson" Content="Format JSON" Style="{StaticResource Btn.Subtle}" Margin="14,0,0,0"/>
                    <Button x:Name="BtnUseExample" Content="Insert example" Style="{StaticResource Btn.Subtle}"/>
                  </StackPanel>
                  <TextBox x:Name="TxtBody" Style="{StaticResource Editor}" Height="190" IsEnabled="False"/>
                  <Grid x:Name="GridBodyFile" Margin="0,9,0,0" Visibility="Collapsed">
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="*"/>
                      <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBox Grid.Column="0" x:Name="TxtBodyFile"/>
                    <Button Grid.Column="1" x:Name="BtnBrowseBody" Content="Browse" Style="{StaticResource Btn.Secondary}" Margin="8,0,0,0"/>
                  </Grid>
                  <TextBlock x:Name="TxtBodyHint" Style="{StaticResource Text.Caption}" TextWrapping="Wrap" Margin="0,7,0,0"/>
                </StackPanel>
              </TabItem>

              <TabItem Header="Headers">
                <StackPanel Margin="0,10,0,0">
                  <TextBlock Text="One header per line, formatted as Name: Value" Style="{StaticResource Text.Label}"/>
                  <TextBox x:Name="TxtHeaders" Style="{StaticResource Editor}" Height="130"/>
                  <TextBlock Style="{StaticResource Text.Caption}" TextWrapping="Wrap" Margin="0,7,0,0"
                             Text="Authorization is supplied automatically and cannot be set here. Authorization, Cookie, Host, Content-Length, Connection, and Transfer-Encoding are blocked."/>
                </StackPanel>
              </TabItem>

              <TabItem Header="Options">
                <Grid Margin="0,10,0,0">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <StackPanel Grid.Column="0" Margin="0,0,18,0">
                    <TextBlock Text="Long-running operations" Style="{StaticResource Text.Label}"/>
                    <CheckBox x:Name="ChkNoWait" Content="Return immediately, do not poll (-NoWait)"/>
                    <TextBlock Text="Poll interval (seconds)" Style="{StaticResource Text.Label}" Margin="0,10,0,4"/>
                    <TextBox x:Name="TxtPollInterval" Text="5" Width="110" HorizontalAlignment="Left"/>
                    <TextBlock Text="Timeout (seconds)" Style="{StaticResource Text.Label}" Margin="0,10,0,4"/>
                    <TextBox x:Name="TxtTimeout" Text="7200" Width="110" HorizontalAlignment="Left"/>
                    <TextBlock Style="{StaticResource Text.Caption}" TextWrapping="Wrap" Margin="0,6,0,0"
                               Text="Use Cancel to stop polling. Zero-timeout waiting is not offered here."/>
                  </StackPanel>
                  <StackPanel Grid.Column="1">
                    <TextBlock Text="Output" Style="{StaticResource Text.Label}"/>
                    <CheckBox x:Name="ChkRawOutput" Content="Raw response, do not pretty-print (-RawOutput)"/>
                    <TextBlock Text="Save response to Output folder as" Style="{StaticResource Text.Label}" Margin="0,10,0,4"/>
                    <TextBox x:Name="TxtOutputFile" ToolTip="File name only. Written inside the package Output folder."/>
                    <Separator/>
                    <TextBlock Text="Diagnostics and package" Style="{StaticResource Text.Label}"/>
                    <CheckBox x:Name="ChkDebugLogging" Content="Verbose debug logging (-DebugLogging)"/>
                    <CheckBox x:Name="ChkEnforceSignature" Content="Enforce Authenticode signatures (-EnforceSignatureValidation)"/>
                    <CheckBox x:Name="ChkPreferBundled" Content="Force bundled modules (-PreferBundledModules)"/>
                    <Button x:Name="BtnSelfTest" Content="Run package self-test" Style="{StaticResource Btn.Secondary}"
                            HorizontalAlignment="Left" Margin="0,10,0,0"/>
                  </StackPanel>
                </Grid>
              </TabItem>
              <TabItem Header="Defaults">
                <StackPanel Margin="0,10,0,0">
                  <TextBlock Text="Pre-filled parameter values, one per line, formatted as name = value" Style="{StaticResource Text.Label}"/>
                  <TextBox x:Name="TxtDefaults" Style="{StaticResource Editor}" Height="150"/>
                  <StackPanel Orientation="Horizontal" Margin="0,9,0,0">
                    <Button x:Name="BtnDefaultsApply" Content="Apply to current operation" Style="{StaticResource Btn.Secondary}" Margin="0,0,8,0"/>
                    <Button x:Name="BtnDefaultsSave" Content="Save" Style="{StaticResource Btn.Secondary}" Margin="0,0,8,0"
                            ToolTip="Save these values so they load automatically next time"/>
                    <Button x:Name="BtnDefaultsSaveAs" Content="Save as" Style="{StaticResource Btn.Subtle}" Margin="0,0,8,0"/>
                    <Button x:Name="BtnDefaultsLoad" Content="Load" Style="{StaticResource Btn.Subtle}" Margin="0,0,8,0"/>
                    <Button x:Name="BtnDefaultsClear" Content="Clear" Style="{StaticResource Btn.Subtle}"/>
                  </StackPanel>
                  <Border Background="{DynamicResource State.WarningBg}" CornerRadius="4" Padding="10,7" Margin="0,10,0,0">
                    <TextBlock Style="{StaticResource Text.Caption}" TextWrapping="Wrap"
                               Text="These values contain subscription IDs and other non-public identifiers. Save keeps a private copy encrypted with your Windows account, or exports an unencrypted copy you can share with your team."/>
                  </Border>
                  <TextBlock x:Name="TxtDefaultsPath" Style="{StaticResource Text.Caption}" TextWrapping="Wrap" Margin="0,8,0,0"/>
                </StackPanel>
              </TabItem>
            </TabControl>
          </StackPanel>
        </ScrollViewer>

        <!-- Pinned action bar: the primary action never scrolls out of view -->
        <Border Grid.Row="1" Background="{DynamicResource Bg.Layer}" BorderBrush="{DynamicResource Stroke.Default}"
                BorderThickness="0,1,0,0" Padding="18,10">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBlock x:Name="TxtValidation" Grid.Column="0" Style="{StaticResource Text.Caption}"
                       VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
            <StackPanel Grid.Column="1" Orientation="Horizontal">
              <Button x:Name="BtnCopyCli" Content="Copy as CLI" Style="{StaticResource Btn.Subtle}" Margin="0,0,8,0"
                      ToolTip="Copy the equivalent ArmClient-PS.ps1 command line"/>
              <Button x:Name="BtnCancel" Content="Cancel" Style="{StaticResource Btn.Secondary}" Margin="0,0,8,0" IsEnabled="False"/>
              <Button x:Name="BtnSend" Content="Send _request" Style="{StaticResource Btn.Primary}" MinWidth="140"/>
            </StackPanel>
          </Grid>
        </Border>
        </Grid>

        <!-- A 1px rule for looks, with a 6px transparent grab area on top of it. -->
        <Border Grid.Row="1" Height="1" VerticalAlignment="Center" Background="{DynamicResource Stroke.Default}"/>
        <GridSplitter Grid.Row="1" Height="6" HorizontalAlignment="Stretch" VerticalAlignment="Center"
                      Background="Transparent" ResizeDirection="Rows" ResizeBehavior="PreviousAndNext"
                      Cursor="SizeNS" ToolTip="Drag to resize the response pane"/>

        <!-- Response -->
        <Grid Grid.Row="2" Background="{DynamicResource Bg.LayerAlt}">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>

          <Grid Grid.Row="0" Margin="18,10,18,0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
              <Border x:Name="BorderStatusChip" CornerRadius="4" Padding="9,3" Visibility="Collapsed"
                      Background="{DynamicResource State.Success}">
                <TextBlock x:Name="TxtStatusChip" Text="200" Foreground="White" FontWeight="SemiBold" FontSize="11.5"/>
              </Border>
              <TextBlock x:Name="TxtElapsed" Style="{StaticResource Text.Caption}" Margin="10,0,0,0" VerticalAlignment="Center"/>
            </StackPanel>
            <StackPanel Grid.Column="2" Orientation="Horizontal">
              <Button x:Name="BtnReveal" Content="Reveal raw" Style="{StaticResource Btn.Subtle}" IsEnabled="False"
                      ToolTip="Temporarily show unredacted content"/>
              <Button x:Name="BtnCopyResponse" Content="Copy" Style="{StaticResource Btn.Subtle}" IsEnabled="False"/>
              <Button x:Name="BtnSaveResponse" Content="Save" Style="{StaticResource Btn.Subtle}" IsEnabled="False"/>
              <Button x:Name="BtnClearLog" Content="Clear log" Style="{StaticResource Btn.Subtle}"/>
            </StackPanel>
          </Grid>

          <TabControl Grid.Row="1" x:Name="TabResponse" Margin="18,4,18,12">
            <TabItem Header="Response">
              <Grid Margin="0,8,0,0">
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <Border x:Name="BorderRedactNotice" Grid.Row="0" CornerRadius="4" Padding="10,6" Margin="0,0,0,8"
                        Background="{DynamicResource Accent.Subtle}" Visibility="Collapsed">
                  <TextBlock x:Name="TxtRedactNotice" Style="{StaticResource Text.Caption}" TextWrapping="Wrap"/>
                </Border>
                <TextBox Grid.Row="1" x:Name="TxtResponse" Style="{StaticResource Editor}" IsReadOnly="True"
                         VerticalScrollBarVisibility="Auto"/>
                <TextBlock x:Name="TxtResponseEmpty" Grid.Row="1" Text="No response yet. Build a request and select Send request."
                           IsHitTestVisible="False" HorizontalAlignment="Center" VerticalAlignment="Center"
                           Foreground="{DynamicResource Text.Tertiary}" FontSize="12.5"/>
              </Grid>
            </TabItem>
            <TabItem Header="Headers">
              <TextBox x:Name="TxtResponseHeaders" Style="{StaticResource Editor}" IsReadOnly="True" Margin="0,8,0,0"/>
            </TabItem>
            <TabItem Header="Activity log">
              <TextBox x:Name="TxtLog" Style="{StaticResource Editor}" IsReadOnly="True" Margin="0,8,0,0"
                       VerticalScrollBarVisibility="Auto"/>
            </TabItem>
          </TabControl>
        </Grid>
      </Grid>
    </Grid>

    <!-- ============ Status bar ============ -->
    <Border Grid.Row="4" Background="{DynamicResource Bg.Layer}" BorderBrush="{DynamicResource Stroke.Default}" BorderThickness="0,1,0,0">
      <Grid Margin="18,7">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock x:Name="TxtStatus" Grid.Column="0" Style="{StaticResource Text.Caption}" Text="Starting"
                   TextTrimming="CharacterEllipsis" VerticalAlignment="Center"/>
        <TextBlock x:Name="TxtCorrelation" Grid.Column="1" Style="{StaticResource Text.Caption}"
                   FontFamily="Cascadia Mono, Consolas" FontSize="11" VerticalAlignment="Center"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

# ==============================================================================
# REGION 6  Window construction
# ==============================================================================

function New-GuiWindow {
    param([Parameter(Mandatory = $true)][string]$Markup)
    $stringReader = [System.IO.StringReader]::new($Markup)
    $xmlReader = [System.Xml.XmlReader]::Create($stringReader)
    try { return [System.Windows.Markup.XamlReader]::Load($xmlReader) }
    finally { $xmlReader.Close(); $stringReader.Close() }
}

$script:Window = New-GuiWindow -Markup $script:XamlMarkup

$controlNames = @(
    'TxtVersion', 'CmbEnvironment', 'BtnSignIn', 'BtnSignOut', 'BtnTenant', 'BtnTheme', 'BtnDefaults', 'BtnGuide',
    'BorderLogoFallback', 'ImgLogo',
    'BorderContext', 'BorderEnvChip', 'TxtEnvChip', 'TxtContext', 'TxtIntegrity', 'PrgBusy',
    'TxtSearch', 'TxtSearchHint', 'ChkDeployedOnly', 'TreeCatalog', 'MenuCatalog', 'MenuDocs', 'MenuCopyDocs',
    'BtnDiscover', 'TxtCatalogStatus',
    'ScrollRequest', 'PanelWelcome', 'BtnWelcomeClose',
    'ExpGuideSignIn', 'ExpGuideFind', 'ExpGuideFill', 'ExpGuideSend', 'ExpGuideDefaults',
    'ExpGuideShortcuts', 'ExpGuideSafety',
    'BorderProvenance', 'TxtProvenance', 'PanelScope', 'CmbScope', 'TxtScopeEvidence',
    'RbPreset', 'RbPath', 'RbUri', 'PanelPreset', 'PanelPath', 'PanelUri',
    'TxtPresetName', 'TxtPresetDesc', 'TxtPresetPath', 'PnlPresetParams', 'TxtPresetNotes', 'BtnDocs',
    'TxtRelativePath', 'TxtUri',
    'BorderMethodChip', 'TxtMethodChip', 'CmbMethod', 'ChkOverrideMethod',
    'CmbApiVersion', 'ChkOverrideApiVersion', 'TxtEffective', 'TxtValidation',
    'BtnCopyCli', 'BtnCancel', 'BtnSend', 'TabRequest',
    'RbBodyNone', 'RbBodyInline', 'RbBodyFile', 'BtnFormatJson', 'BtnUseExample',
    'TxtBody', 'GridBodyFile', 'TxtBodyFile', 'BtnBrowseBody', 'TxtBodyHint', 'TxtHeaders',
    'ChkNoWait', 'TxtPollInterval', 'TxtTimeout', 'ChkRawOutput', 'TxtOutputFile',
    'ChkDebugLogging', 'ChkEnforceSignature', 'ChkPreferBundled', 'BtnSelfTest',
    'TxtDefaults', 'BtnDefaultsApply', 'BtnDefaultsSave', 'BtnDefaultsSaveAs',
    'BtnDefaultsLoad', 'BtnDefaultsClear', 'TxtDefaultsPath',
    'BorderStatusChip', 'TxtStatusChip', 'TxtElapsed',
    'BtnReveal', 'BtnCopyResponse', 'BtnSaveResponse', 'BtnClearLog',
    'TabResponse', 'BorderRedactNotice', 'TxtRedactNotice', 'TxtResponse', 'TxtResponseEmpty', 'TxtResponseHeaders', 'TxtLog',
    'TxtStatus', 'TxtCorrelation'
)

$ui = $script:App.Ui
foreach ($name in $controlNames) {
    $found = $script:Window.FindName($name)
    if ($null -eq $found) { throw "The window markup is missing a control named '$name'." }
    $ui[$name] = $found
}

# ==============================================================================
# REGION 7  Theme
# ==============================================================================

function Set-GuiTheme {
    param([Parameter(Mandatory = $true)][ValidateSet('Light', 'Dark')][string]$Name)
    $markup = if ($Name -eq 'Dark') { $XamlPaletteDark } else { $XamlPaletteLight }
    $dict = [System.Windows.Markup.XamlReader]::Parse($markup)
    $script:Window.Resources.MergedDictionaries.Clear()
    $script:Window.Resources.MergedDictionaries.Add($dict)
    $script:App.Theme = $Name
    Update-MethodChip
    Update-ContextBanner
}

$initialTheme = $Theme
if ($initialTheme -eq 'Auto') {
    $initialTheme = if (Get-WindowsUsesLightTheme) { 'Light' } else { 'Dark' }
}

# Prefers the packaged logo and keeps the lettermark for a standalone copy of this file.
function Initialize-Branding {
    $logoPath = Join-Path $GuiRoot 'assets\armclient-ps-logo.png'
    if (-not (Test-Path -LiteralPath $logoPath -PathType Leaf)) { return }
    try {
        $bitmap = [System.Windows.Media.Imaging.BitmapImage]::new()
        $bitmap.BeginInit()
        # OnLoad reads the file fully so the asset is not locked for the process lifetime.
        $bitmap.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $bitmap.UriSource = [System.Uri]::new([System.IO.Path]::GetFullPath($logoPath))
        $bitmap.EndInit()
        $bitmap.Freeze()
        $ui.ImgLogo.Source = $bitmap
        $ui.ImgLogo.Visibility = 'Visible'
        $ui.BorderLogoFallback.Visibility = 'Collapsed'
        $script:Window.Icon = $bitmap
    }
    catch {
        # An unreadable or corrupt asset must never stop the tool from starting.
        $ui.ImgLogo.Visibility = 'Collapsed'
        $ui.BorderLogoFallback.Visibility = 'Visible'
    }
}

# ==============================================================================
# REGION 8  Presentation helpers
# ==============================================================================

$script:MethodColors = @{
    GET    = '#0E7A0D'; POST = '#0078D4'; PUT = '#7A52B3'
    PATCH  = '#9A5416'; DELETE = '#C42B1C'
}

# Learn slugs are irregular and cannot be derived from the ARM namespace, so every
# entry here was confirmed with an HTTP HEAD returning 200.
$script:ArmProviderDocsMap = @{
    'microsoft.advisor'             = 'advisor'
    'microsoft.apimanagement'       = 'apimanagement'
    'microsoft.appconfiguration'    = 'appconfiguration'
    'microsoft.authorization'       = 'authorization'
    'microsoft.automation'          = 'automation'
    'microsoft.billing'             = 'billing'
    'microsoft.cache'               = 'redis'
    'microsoft.cognitiveservices'   = 'cognitiveservices'
    'microsoft.communication'       = 'communication'
    'microsoft.compute'             = 'compute'
    'microsoft.containerregistry'   = 'containerregistry'
    'microsoft.containerservice'    = 'aks'
    'microsoft.costmanagement'      = 'costmanagement'
    'microsoft.datafactory'         = 'datafactory'
    'microsoft.documentdb'          = 'cosmos-db'
    'microsoft.eventhub'            = 'eventhub'
    'microsoft.insights'            = 'monitor'
    'microsoft.keyvault'            = 'keyvault'
    'microsoft.managedidentity'     = 'managedidentity'
    'microsoft.management'          = 'managementgroups'
    'microsoft.network'             = 'network'
    'microsoft.notificationhubs'    = 'notificationhubs'
    'microsoft.operationalinsights' = 'loganalytics'
    'microsoft.policyinsights'      = 'policy'
    'microsoft.recoveryservices'    = 'recoveryservices'
    'microsoft.resourcehealth'      = 'resourcehealth'
    'microsoft.resources'           = 'resources'
    'microsoft.security'            = 'securitycenter'
    'microsoft.servicebus'          = 'servicebus'
    'microsoft.signalrservice'      = 'signalr'
    'microsoft.sql'                 = 'sql'
    'microsoft.storage'             = 'storagerp'
    'microsoft.subscription'        = 'subscription'
    'microsoft.web'                 = 'appservice'
}

# Returns the docs target plus how precise it is, so the UI can word the link
# honestly instead of promising a page that may not exist.
function Get-ArmDocsUrl {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Operation)

    if ($null -eq $Operation) { return $null }

    $provider = [string](Get-SafeProperty -InputObject $Operation -Name 'ProviderNamespace')
    $resourceType = [string](Get-SafeProperty -InputObject $Operation -Name 'ResourceType')
    $name = [string](Get-SafeProperty -InputObject $Operation -Name 'Name')

    # A discovered operation carries its namespace in the RBAC name, not the property.
    if ([string]::IsNullOrWhiteSpace($provider) -and $name.Contains('/')) {
        $provider = ($name -split '/')[0]
    }

    $slug = ''
    if ($provider) {
        $key = $provider.ToLowerInvariant()
        if ($script:ArmProviderDocsMap.ContainsKey($key)) { $slug = [string]$script:ArmProviderDocsMap[$key] }
    }

    if ($slug) {
        return [pscustomobject]@{
            Url     = 'https://learn.microsoft.com/en-us/rest/api/' + $slug + '/'
            Quality = 'Provider'
            Label   = 'REST API reference for ' + $provider
        }
    }

    $terms = @($provider, $resourceType, $name) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($terms.Count -eq 0) { $terms = @('Azure Resource Manager REST') }
    $query = [System.Uri]::EscapeDataString((($terms | Select-Object -Unique) -join ' '))
    return [pscustomobject]@{
        Url     = 'https://learn.microsoft.com/en-us/search/?terms=' + $query
        Quality = 'Search'
        Label   = 'Search Microsoft Learn'
    }
}

# The URL is built partly from ARM provider metadata, so it is treated as untrusted.
# Start-Process shell-executes its first argument, which would happily launch a local
# file or a protocol handler, so this allowlists rather than sanitizes.
function Open-DocsLink {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Url)

    $uri = $null
    $ok = [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)
    if ($ok) {
        $ok = ([string]::Equals($uri.Scheme, 'https', [System.StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals($uri.IdnHost, 'learn.microsoft.com', [System.StringComparison]::OrdinalIgnoreCase) -and
            [string]::IsNullOrEmpty($uri.UserInfo) -and
            $uri.IsDefaultPort)
    }
    if (-not $ok) {
        throw 'That documentation link was blocked because it is not an https address on learn.microsoft.com.'
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $uri.AbsoluteUri
    $startInfo.UseShellExecute = $true
    $null = [System.Diagnostics.Process]::Start($startInfo)
}

# Deep-link service prefixes. These differ from the provider-root map above: the root
# page and the operation pages do not always live under the same slug. Every entry was
# confirmed with an HTTP HEAD returning 200.
$script:ArmDocsDeepSlugs = @{
    'microsoft.communication' = 'communication/resourcemanager'
    'microsoft.keyvault'      = 'keyvault/keyvault'
    'microsoft.insights'      = 'monitor'
    'microsoft.storage'       = 'storagerp'
    'microsoft.web'           = 'appservice'
    'microsoft.containerservice' = 'aks'
    'microsoft.documentdb'    = 'cosmos-db'
    'microsoft.operationalinsights' = 'loganalytics'
    'microsoft.management'    = 'managementgroups'
    'microsoft.security'      = 'securitycenter'
    'microsoft.cache'         = 'redis'
    'microsoft.signalrservice' = 'signalr'
    'microsoft.policyinsights' = 'policy'
}

function ConvertTo-KebabCase {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $step = [regex]::Replace($Value, '([a-z0-9])([A-Z])', '$1-$2')
    $step = [regex]::Replace($step, '([A-Z]+)([A-Z][a-z])', '$1-$2')
    $step = [regex]::Replace($step, '[^A-Za-z0-9]+', '-')
    return $step.Trim('-').ToLowerInvariant()
}

# Ordered candidate URLs, most specific first. The caller walks them with an HTTP HEAD
# because derivation is right about three quarters of the time, not always.
function Get-ArmDocsCandidate {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Operation)
    if ($null -eq $Operation) { return @() }

    $provider = [string](Get-SafeProperty -InputObject $Operation -Name 'ProviderNamespace')
    $resourceType = [string](Get-SafeProperty -InputObject $Operation -Name 'ResourceType')
    $name = [string](Get-SafeProperty -InputObject $Operation -Name 'Name')
    $template = [string](Get-SafeProperty -InputObject $Operation -Name 'RelativePathTemplate')
    if ([string]::IsNullOrWhiteSpace($provider) -and $name.Contains('/')) { $provider = ($name -split '/')[0] }

    $key = ''
    if ($provider) { $key = $provider.ToLowerInvariant() }
    $deep = ''
    if ($key -and $script:ArmDocsDeepSlugs.ContainsKey($key)) { $deep = [string]$script:ArmDocsDeepSlugs[$key] }
    elseif ($key -and $script:ArmProviderDocsMap.ContainsKey($key)) { $deep = [string]$script:ArmProviderDocsMap[$key] }
    elseif ($key -and $key.StartsWith('microsoft.')) { $deep = $key.Substring(10) }

    $root = ''
    if ($key -and $script:ArmProviderDocsMap.ContainsKey($key)) { $root = [string]$script:ArmProviderDocsMap[$key] }

    $group = ''
    if ($resourceType) {
        $segments = @($resourceType -split '/' | Where-Object { $_ })
        if ($segments.Count -gt 0) { $group = ConvertTo-KebabCase -Value $segments[-1] }
    }

    # The request template is a better signal than the operation name: a curated preset
    # has no RBAC verb at all, and the template says plainly whether this addresses a
    # collection, a single item, or a named action.
    $action = ''
    $lastSegment = ''
    if ($template) {
        $segments = @($template.TrimEnd('/') -split '/' | Where-Object { $_ })
        if ($segments.Count -gt 0) { $lastSegment = $segments[-1] }
    }
    if ($lastSegment -and $lastSegment -notmatch '^\{.*\}$') {
        $kebabLast = ConvertTo-KebabCase -Value $lastSegment
        if ($kebabLast -eq $group) { $action = 'list' } else { $action = $kebabLast }
    }
    elseif ($lastSegment) {
        # Addresses a single item, so the method decides which operation it is.
        $verb = [string](Get-SafeProperty -InputObject $Operation -Name 'Method')
        if ($verb -eq 'PUT') { $action = 'create-or-update' }
        elseif ($verb -eq 'PATCH') { $action = 'update' }
        elseif ($verb -eq 'DELETE') { $action = 'delete' }
        else { $action = 'get' }
    }

    if (-not $action) {
        $tail = ''
        if ($name.Contains('/')) { $tail = @($name -split '/')[-1] }
        if ($tail -eq 'action') {
            $parts = @($name -split '/')
            if ($parts.Count -ge 2) { $action = ConvertTo-KebabCase -Value $parts[$parts.Count - 2] }
        }
        elseif ($tail -eq 'read') { $action = 'get' }
        elseif ($tail -eq 'write') { $action = 'create-or-update' }
        elseif ($tail -eq 'delete') { $action = 'delete' }
        elseif ($tail) { $action = ConvertTo-KebabCase -Value $tail }
    }

    $candidates = New-Object System.Collections.Generic.List[object]
    if ($deep -and $group -and $action) {
        $exactUrl = 'https://learn.microsoft.com/en-us/rest/api/{0}/{1}/{2}' -f $deep, $group, $action
        $candidates.Add([pscustomobject]@{
                Url = $exactUrl; Quality = 'Exact'; Label = 'Documentation for this operation'
            }) | Out-Null
        # A collection read is often published as list-by-resource-group instead of list.
        if ($action -eq 'list') {
            $altUrl = 'https://learn.microsoft.com/en-us/rest/api/{0}/{1}/list-by-resource-group' -f $deep, $group
            $candidates.Add([pscustomobject]@{
                    Url = $altUrl; Quality = 'Exact'; Label = 'Documentation for this operation'
                }) | Out-Null
        }
    }
    if ($deep -and $group) {
        $typeUrl = 'https://learn.microsoft.com/en-us/rest/api/{0}/{1}' -f $deep, $group
        $candidates.Add([pscustomobject]@{
                Url = $typeUrl; Quality = 'Resource'; Label = 'Documentation for this resource type'
            }) | Out-Null
    }
    if ($root) {
        $candidates.Add([pscustomobject]@{
                Url = 'https://learn.microsoft.com/en-us/rest/api/' + $root + '/'
                Quality = 'Provider'; Label = 'REST API reference for ' + $provider
            }) | Out-Null
    }

    $terms = @($provider, $resourceType, $name) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($terms.Count -eq 0) { $terms = @('Azure Resource Manager REST') }
    $candidates.Add([pscustomobject]@{
            Url = 'https://learn.microsoft.com/en-us/search/?terms=' + [System.Uri]::EscapeDataString((($terms | Select-Object -Unique) -join ' '))
            Quality = 'Search'; Label = 'Search Microsoft Learn'
        }) | Out-Null

    return $candidates.ToArray()
}

# Resolved documentation URLs, keyed by operation name. Kept in memory only: on disk
# it would become a record of which operations were inspected and when.
$script:DocsUrlCache = @{}
$script:DocsCacheLimit = 2048
# Set when the network itself failed, so one outage does not make every later click
# pay another full timeout.
$script:DocsOfflineUntil = [datetime]::MinValue

function Clear-DocsUrlCache {
    $script:DocsUrlCache = @{}
    $script:DocsOfflineUntil = [datetime]::MinValue
}

# Returns the first candidate that exists, or the search fallback. The probe runs on a
# private unauthenticated runspace so it can neither block the UI thread nor occupy the
# shared worker, which would disable Send while a docs lookup ran.
function Resolve-ArmDocsUrl {
    param([Parameter(Mandatory = $true)][object[]]$Candidate, [int]$TimeoutSeconds = 4)

    $probe = @($Candidate | Where-Object { $_.Quality -ne 'Search' })
    $fallback = @($Candidate | Where-Object { $_.Quality -eq 'Search' })[0]
    if ($probe.Count -eq 0) { return $fallback }
    # The search page always exists, so it is never probed.
    if ((Get-Date) -lt $script:DocsOfflineUntil) { return $fallback }

    $urls = @($probe | ForEach-Object { $_.Url })
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = 'MTA'
    $runspace.ThreadOptions = 'ReuseThread'
    $runspace.Open()
    $shell = [PowerShell]::Create()
    $shell.Runspace = $runspace
    $null = $shell.AddScript({
            param($Urls, $Timeout)
            $ProgressPreference = 'SilentlyContinue'
            foreach ($u in $Urls) {
                try {
                    # Redirects are NOT followed: a Location header can leave the allowed
                    # host, and a 3xx from Learn already proves the page exists.
                    $r = Invoke-WebRequest -Uri $u -Method Head -MaximumRedirection 0 `
                        -TimeoutSec $Timeout -UseBasicParsing -ErrorAction Stop
                    if ([int]$r.StatusCode -lt 400) { 'HIT ' + $u; break }
                }
                catch {
                    $status = 0
                    if ($null -ne $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
                    if ($status -ge 300 -and $status -lt 400) { 'HIT ' + $u; break }
                    # Only a genuine "not here" advances the ladder. Anything else is the
                    # network failing, and probing further URLs just repeats the outage.
                    if ($status -ne 404 -and $status -ne 410) { 'OFFLINE'; break }
                }
            }
        }).AddArgument($urls).AddArgument($TimeoutSeconds)

    $async = $shell.BeginInvoke()
    $deadline = (Get-Date).AddSeconds([Math]::Max(2, $TimeoutSeconds * $urls.Count))
    while (-not $async.IsCompleted -and (Get-Date) -lt $deadline) {
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke(
            [System.Windows.Threading.DispatcherPriority]::Background, [action] {}) | Out-Null
        Start-Sleep -Milliseconds 40
    }
    $outcome = ''
    if ($async.IsCompleted) { try { $outcome = [string](@($shell.EndInvoke($async)))[0] } catch { $outcome = '' } }
    else { try { $shell.Stop() } catch { }; $outcome = 'OFFLINE' }
    try { $shell.Dispose() } catch { }
    try { $runspace.Close(); $runspace.Dispose() } catch { }

    if ($outcome -eq 'OFFLINE' -or $outcome -eq '') {
        $script:DocsOfflineUntil = (Get-Date).AddSeconds(60)
        return $fallback
    }
    if ($outcome.StartsWith('HIT ')) {
        $hit = $outcome.Substring(4)
        # Matched against the candidate list, so only a URL this app built can be
        # returned, never anything the server suggested.
        foreach ($c in $probe) { if ($c.Url -eq $hit) { return $c } }
    }
    return $fallback
}

function Update-DocsLink {
    param([AllowNull()][object]$Operation)
    if (-not $ui.ContainsKey('BtnDocs')) { return }
    if ($null -eq $Operation) {
        $ui.BtnDocs.Visibility = 'Collapsed'
        $ui.BtnDocs.Tag = $null
        return
    }
    # The operation is kept, not a URL: the real page is resolved on click so the app
    # makes no network call just because something was selected.
    $ui.BtnDocs.Visibility = 'Visible'
    $ui.BtnDocs.Tag = $Operation
    $ui.BtnDocs.ToolTip = 'Open the Microsoft Learn documentation for ' +
    [string](Get-SafeProperty -InputObject $Operation -Name 'Name') +
    '. The exact page is located when you click.'
}

# Single entry point for the help icon and the tree context menu.
# Reads as a sentence. Composing a label with the name produced "Documentation for
# this operation for AcsEmailServiceList".
function Get-DocsOpenedMessage {
    param([Parameter(Mandatory = $true)][object]$Resolved, [string]$Name)
    switch ([string]$Resolved.Quality) {
        'Exact' { return 'Opened the documentation for ' + $Name }
        'Resource' { return 'Opened the documentation for this resource type. There is no page for ' + $Name + ' itself.' }
        'Provider' { return 'Opened the provider reference. There is no page for ' + $Name + ' itself.' }
        default { return 'No page found for ' + $Name + ', so Microsoft Learn search was opened instead.' }
    }
}

function Show-OperationDocs {
    param([Parameter(Mandatory = $true)][object]$Operation)
    $name = [string](Get-SafeProperty -InputObject $Operation -Name 'Name')
    if ($script:DocsUrlCache.ContainsKey($name)) {
        $cached = $script:DocsUrlCache[$name]
        Open-DocsLink -Url $cached.Url
        Set-Status (Get-DocsOpenedMessage -Resolved $cached -Name $name)
        return
    }
    $candidates = @(Get-ArmDocsCandidate -Operation $Operation)
    if ($candidates.Count -eq 0) { Set-Status 'No documentation could be located for this operation.' -Kind 'Problem'; return }
    Set-Status ('Looking up documentation for {0}' -f $name)
    $previousCursor = $script:Window.Cursor
    $script:Window.Cursor = [System.Windows.Input.Cursors]::AppStarting
    try { $resolved = Resolve-ArmDocsUrl -Candidate $candidates }
    finally { $script:Window.Cursor = $previousCursor }
    if ($script:DocsUrlCache.Count -ge $script:DocsCacheLimit) { $script:DocsUrlCache = @{} }
    $script:DocsUrlCache[$name] = $resolved
    Open-DocsLink -Url $resolved.Url
    Set-Status (Get-DocsOpenedMessage -Resolved $resolved -Name $name)
}

function Update-MethodChip {
    $method = Get-EffectiveMethod
    $hex = $script:MethodColors[$method]
    if (-not $hex) { $hex = '#0078D4' }
    $brush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($hex))
    $ui.TxtMethodChip.Text = $method
    $ui.BorderMethodChip.Background = $brush
    Update-EffectiveRequest
}

# Live preview plus an inline reason the request cannot be sent yet.
function Update-EffectiveRequest {
    if (-not $ui.ContainsKey('TxtEffective')) { return }
    $mode = Get-RequestMode
    $target = '-'
    if ($mode -eq 'Preset') {
        $preset = $script:App.SelectedPreset
        if ($null -ne $preset) { $target = [string]$preset.RelativePathTemplate }
    }
    elseif ($mode -eq 'Path') { $target = [string]$ui.TxtRelativePath.Text }
    else { $target = [string]$ui.TxtUri.Text }
    if ([string]::IsNullOrWhiteSpace($target)) { $target = '-' }
    $ui.TxtEffective.Text = '{0}  {1}' -f (Get-EffectiveMethod), $target

    $hint = ''
    try { $null = Build-RequestArguments }
    catch { $hint = $_.Exception.Message }
    if ([string]::IsNullOrEmpty($hint) -and $null -eq $script:App.Context) {
        $hint = 'Sign in to send. Browsing operations and Copy as CLI work without signing in.'
    }
    $ui.TxtValidation.Text = $hint
    Update-SendAvailability
}

$script:StatusHoldSeconds = 10
$script:StatusGeneration = 0
$script:StatusFadeGeneration = -1
$script:StatusFadeTimer = $null

# Routine progress clears itself so the bar does not keep stale text on screen.
# Anything the user may need to act on is left up permanently.
function Set-Status {
    param([string]$Message, [ValidateSet('Info', 'Problem')][string]$Kind = 'Info')

    $script:StatusGeneration++
    $ui.TxtStatus.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $null)
    $ui.TxtStatus.Opacity = 1
    $ui.TxtStatus.Text = $Message

    if ($null -eq $script:StatusFadeTimer) { return }
    $script:StatusFadeTimer.Stop()
    if ($Kind -eq 'Info' -and -not [string]::IsNullOrWhiteSpace($Message)) { $script:StatusFadeTimer.Start() }
}

function Initialize-StatusFade {
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromSeconds($script:StatusHoldSeconds)
    # Plain scriptblocks on purpose: GetNewClosure would rebind $script: and the
    # generation check below would always compare against null.
    $timer.Add_Tick({
            $script:StatusFadeTimer.Stop()
            $script:StatusFadeGeneration = $script:StatusGeneration
            $fade = [System.Windows.Media.Animation.DoubleAnimation]::new(
                1, 0, [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds(700)))
            # Stop, so opacity returns to 1 for whatever text comes next.
            $fade.FillBehavior = [System.Windows.Media.Animation.FillBehavior]::Stop
            $fade.Add_Completed({
                    # A newer message replaced this one mid-fade, so leave it alone.
                    if ($script:StatusGeneration -ne $script:StatusFadeGeneration) { return }
                    $ui.TxtStatus.Text = ''
                    $ui.TxtStatus.Opacity = 1
                })
            $ui.TxtStatus.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
        })
    $script:StatusFadeTimer = $timer
}

# Log lines are buffered and flushed once per pump tick. Appending and scrolling
# per line makes a long-running operation's output visibly stutter.
function Add-LogLine {
    param([string]$Line)
    if ([string]::IsNullOrEmpty($Line)) { return }
    $script:App.LogLines.Add($Line)
    $null = $script:App.PendingLog.AppendLine($Line)
    if ($null -eq $script:App.Pump -or -not $script:App.Pump.IsEnabled) { Write-LogBuffer }
}

function Write-LogBuffer {
    if ($script:App.PendingLog.Length -eq 0) { return }
    $list = $script:App.LogLines
    if ($list.Count -gt $script:App.MaxLogLines) {
        $list.RemoveRange(0, $list.Count - $script:App.MaxLogLines)
        $ui.TxtLog.Text = ($list -join [Environment]::NewLine) + [Environment]::NewLine
    }
    else { $ui.TxtLog.AppendText($script:App.PendingLog.ToString()) }
    $script:App.PendingLog.Length = 0
    $ui.TxtLog.ScrollToEnd()
}

function Set-Busy {
    param([bool]$IsBusy, [string]$Kind = '')
    $script:App.Busy = $IsBusy
    $script:App.Kind = $Kind
    $ui.PrgBusy.Visibility = if ($IsBusy) { 'Visible' } else { 'Collapsed' }
    $ui.BtnSignIn.IsEnabled = -not $IsBusy
    $ui.BtnSignOut.IsEnabled = (-not $IsBusy) -and ($null -ne $script:App.Context)
    $ui.BtnTenant.IsEnabled = (-not $IsBusy) -and ($null -ne $script:App.Context)
    $ui.BtnSelfTest.IsEnabled = -not $IsBusy
    $ui.BtnCancel.IsEnabled = $IsBusy
    Update-SendAvailability
}

# Sending is the only thing that cannot work signed out, so it is the only thing
# disabled. Browsing operations and Copy as CLI stay available.
function Update-SendAvailability {
    if (-not $ui.ContainsKey('BtnSend')) { return }
    $signedIn = ($null -ne $script:App.Context)
    $ui.BtnSend.IsEnabled = (-not $script:App.Busy) -and $signedIn
    $ui.BtnSend.ToolTip = if ($signedIn) { 'Send the request shown above' }
    else { 'Sign in first. You can still browse operations and use Copy as CLI.' }
}

function Show-Message {
    param([string]$Text, [string]$Caption = 'ArmClient-PS', [string]$Icon = 'Information')
    [System.Windows.MessageBox]::Show($script:Window, $Text, $Caption, 'OK', $Icon) | Out-Null
}

function Confirm-Action {
    param([string]$Text, [string]$Caption = 'Confirm')
    $result = [System.Windows.MessageBox]::Show($script:Window, $Text, $Caption, 'YesNo', 'Warning', 'No')
    return ($result -eq 'Yes')
}

# ==============================================================================
# REGION 9  Worker runspace
# The tool is dot-sourced with -ToolVersion, which initializes package paths and
# defines every function without importing modules or authenticating. Requests
# then run through wrapper functions whose locals shadow the script parameters.
# ==============================================================================

$WorkerBootstrap = @'
param([string]$ArmScriptPath)

$ErrorActionPreference = 'Stop'
. $ArmScriptPath -ToolVersion | Out-Null

$expectedRoot = (Get-Item -LiteralPath $ArmScriptPath).DirectoryName
if ($SessionState.ScriptRoot -ne $expectedRoot) {
    throw "ArmClient-PS resolved its package root to '$($SessionState.ScriptRoot)' instead of '$expectedRoot'."
}

# Names the core script treats as explicit user overrides.
$global:ArmKnownParameters = @(
    'Method','Uri','RelativePath','Operation','OperationParameters','ApiVersion',
    'Body','BodyFile','OutputFile','RawOutput','NoWait','Headers','TenantId','SubscriptionId'
)

# Captured before any request mutates them, so every request starts from a known baseline.
$global:ArmPristinePoll = @{
    Default = $Configuration['DefaultPollIntervalSeconds']
    Max     = $Configuration['MaxPollIntervalSeconds']
    Timeout = $Configuration['LongRunningTimeoutSeconds']
}

function global:Initialize-ArmRuntime {
    param([string]$Environment = 'AzureCloud', [bool]$DebugLogging = $false,
          [bool]$EnforceSignature = $false, [bool]$PreferBundled = $false)
    $SessionState['SelectedEnvironment'] = $Environment
    $SessionState['DebugEnabled'] = $DebugLogging
    $EnforceSignatureValidation = [switch]$EnforceSignature
    $PreferBundledModules = [switch]$PreferBundled
    if ($SessionState.ResolvedModules.Count -lt 1) {
        Import-BundledModules | Out-Null
        Initialize-AzProcessSecurity
    }
    Get-CurrentAzContextSafe
}

function global:Connect-ArmGui {
    param([string]$Environment = 'AzureCloud', [string]$TenantId, [string]$SubscriptionId,
          [bool]$UseDeviceCode = $false)
    $SessionState['SelectedEnvironment'] = $Environment
    $environmentObject = Get-AzEnvironmentSafe -Name $Environment
    if ($null -eq $environmentObject) { throw "Azure environment '$Environment' is not available in the resolved Az.Accounts runtime." }
    if (-not (Test-TenantIdentifier -Value $TenantId)) { throw "TenantId '$TenantId' is not a valid GUID or verified domain name." }
    if (-not (Test-SubscriptionIdentifier -Value $SubscriptionId)) { throw "SubscriptionId '$SubscriptionId' is not a valid GUID." }

    $connect = @{ Environment = $environmentObject.Name; Scope = 'Process'; ErrorAction = 'Stop' }
    if ($TenantId) { $connect['Tenant'] = $TenantId }
    if ($SubscriptionId) { $connect['Subscription'] = $SubscriptionId }
    if ($UseDeviceCode) { $connect['UseDeviceAuthentication'] = $true }
    $null = Connect-AzAccount @connect
    $SessionState['AuthenticatedByScript'] = $true
    Get-CurrentAzContextSafe
}

function global:Get-ArmGuiTenant { @(Get-AzTenant -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ Id = [string]$_.Id; Name = [string]$_.Name; Domain = [string]$_.DefaultDomain } }) }

# Reports the active context without Initialize-ArmRuntime's side effects, so a failed
# tenant switch can ask what actually survived.
function global:Get-ArmGuiContext { Get-CurrentAzContextSafe }

function global:Get-ArmGuiSubscription {
    @(Get-AzSubscription -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Id = [string]$_.Id; Name = [string]$_.Name; State = [string]$_.State; TenantId = [string]$_.TenantId } })
}

function global:Set-ArmGuiSubscription {
    param([Parameter(Mandatory=$true)][string]$SubscriptionId)
    Set-TargetSubscription -TargetSubscriptionId $SubscriptionId
    Get-CurrentAzContextSafe
}

function global:Disconnect-ArmGui {
    Clear-ArmClientPsContext
    $SessionState['ProviderMetadataCache'] = @{}
    $null
}

function global:Get-ArmGuiCatalog {
    @(Get-ArmOperationPresetCatalog | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name; Category = $_.Category; Description = $_.Description
            Method = $_.Method; RelativePathTemplate = $_.RelativePathTemplate
            DefaultApiVersion = $_.DefaultApiVersion; Aliases = @($_.Aliases)
            RequiredParameters = @($_.RequiredParameters); OptionalParameters = @($_.OptionalParameters)
            KnownApiVersions = @($_.KnownApiVersions); Notes = @($_.Notes)
            ProviderNamespace = $_.ProviderNamespace; ResourceType = $_.ResourceType
            IsPreset = $true
            # Pre-uppercased once here so the search hot path is pure Ordinal work.
            SearchBlob = (@(@($_.Name, $_.Category, $_.Description, $_.Method, $_.RelativePathTemplate,
                            $_.ProviderNamespace, $_.ResourceType) + @($_.Aliases) |
                        Where-Object { -not [string]::IsNullOrEmpty($_) }) -join ' ').ToUpperInvariant()
            HasDefaultBody = ($null -ne $_.DefaultBodyTemplate)
            ExampleBody = $(if ($null -ne $_.ExampleBody) { $_.ExampleBody | ConvertTo-Json -Depth 20 } else { '' })
            ExampleParameters = $(if ($null -ne $_.ExampleParameters) { $_.ExampleParameters } else { @{} })
        } })
}

# Structural redaction. Key-name matching catches secrets the text redactor would miss.
$global:ArmSecretMemberPattern = '^(authorization|proxy-authorization|x-ms-authorization-auxiliary|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|secrets|password|pwd|assertion|cookie|set-cookie|sig|account[_-]?key|primaryKey|secondaryKey|primaryMasterKey|secondaryMasterKey|primaryReadonlyMasterKey|secondaryReadonlyMasterKey|primaryConnectionString|secondaryConnectionString|shared[_-]?access[_-]?(key|signature)|api[_-]?key|subscription[_-]?key|private[_-]?key|connection[_ -]?string|connectionStrings|customData|scriptContent|commandToExecute|adminPassword|servicePrincipalProfile|clientSecret|keyData|certificatePassword|storageAccountKey)$'

# 'value' is a secret only when scalar. Every ARM list response wraps its results in a top-level 'value' array.
$global:ArmScalarSecretMemberPattern = '^(value|keyValue|certificate|thumbprint)$'

function global:Protect-ArmJsonNode {
    param([AllowNull()][object]$Value, [int]$Depth = 0)
    if ($null -eq $Value -or $Depth -gt 60) { return $Value }
    if ($Value -is [string]) { return (Redact-SensitiveText -Text $Value) }
    if ($Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [System.Collections.IDictionary]) {
        # Build explicitly and return as one pipeline item, otherwise single-element
        # arrays collapse to scalars and nested arrays flatten.
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) { $items.Add((Protect-ArmJsonNode -Value $item -Depth ($Depth + 1))) }
        return , $items.ToArray()
    }
    $result = [ordered]@{}
    $members = if ($Value -is [System.Collections.IDictionary]) {
        @($Value.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Value[$_] } })
    } else {
        @($Value.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })
    }
    foreach ($member in $members) {
        $isScalar = ($null -eq $member.Value) -or ($member.Value -is [string]) -or ($member.Value -is [ValueType])
        if (($member.Name -match $global:ArmSecretMemberPattern) -or
            ($isScalar -and $member.Name -match $global:ArmScalarSecretMemberPattern)) {
            $result[$member.Name] = '[REDACTED]'
        }
        else { $result[$member.Name] = Protect-ArmJsonNode -Value $member.Value -Depth ($Depth + 1) }
    }
    [pscustomobject]$result
}

function global:ConvertTo-ArmRedactedText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    try {
        # PowerShell 7 enumerates a top-level JSON array into the pipeline, so a
        # single-element document would arrive here as a bare object.
        $isArrayDocument = $Text.TrimStart().StartsWith('[')
        $parsed = $Text | ConvertFrom-Json -ErrorAction Stop
        if ($isArrayDocument) { $parsed = @($parsed) }
        $safe = Protect-ArmJsonNode -Value $parsed
        # -InputObject, not a pipe: piping re-enumerates and collapses a top-level array.
        return (Redact-SensitiveText -Text (ConvertTo-Json -InputObject $safe -Depth 100))
    }
    catch { return (Redact-SensitiveText -Text $Text) }
}

# Writes the redacted response inside the package Output folder. The core script's own
# -OutputFile path is deliberately bypassed because it would persist unredacted content.
function global:Save-ArmGuiRedactedOutput {
    param([Parameter(Mandatory=$true)][string]$FileName,
          [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Content)
    $leaf = [IO.Path]::GetFileName($FileName)
    if ($leaf -cne $FileName -or [string]::IsNullOrWhiteSpace($leaf)) { throw 'The output path must be a leaf file name.' }
    # .NET Core keeps 'name:stream' intact where .NET Framework strips it, so reject separators explicitly.
    if ($leaf.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or $leaf.Contains(':')) { throw 'The output file name contains an invalid character.' }
    if ($leaf.EndsWith('.') -or [char]::IsWhiteSpace($leaf[$leaf.Length - 1])) { throw 'The output file name cannot end with a period or whitespace.' }
    $deviceStem = ($leaf -split '\.', 2)[0]
    if ($deviceStem -match '^(?i:CON|CONIN\$|CONOUT\$|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { throw "The reserved device name '$deviceStem' cannot be used." }
    Ensure-Directory -Path $SessionState.OutputPath
    $rootInfo = Get-Item -LiteralPath $SessionState.OutputPath -Force -ErrorAction Stop
    if (($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'The Output folder must not be a symbolic link or junction.' }
    $root = [IO.Path]::GetFullPath($rootInfo.FullName).TrimEnd('\', '/')
    $destination = [IO.Path]::GetFullPath((Join-Path $root $leaf))
    if (-not $destination.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The output path escaped the package Output folder.'
    }
    # CreateNew refuses to follow an existing symlink or hard link at the destination.
    $stream = [IO.FileStream]::new($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
        try { $writer.Write($Content) } finally { $writer.Dispose() }
    }
    finally { $stream.Dispose() }
    $destination
}

# The single request entry point. Its parameters shadow the script's own, so the
# entire ArmClient-PS call tree observes exactly what the GUI supplied.
function global:Invoke-ArmGuiRequest {
    [CmdletBinding()]
    param(
        [ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method = 'GET',
        [System.Uri]$Uri,
        [string]$RelativePath,
        [string]$Operation,
        [hashtable]$OperationParameters,
        [string]$ApiVersion,
        [string]$Body,
        [string]$BodyFile,
        [string]$OutputFile,
        [switch]$RawOutput,
        [switch]$NoWait,
        [hashtable]$Headers,
        [string]$TenantId,
        [string]$SubscriptionId,
        [int]$PollIntervalSeconds,
        [int]$LongRunningTimeoutSeconds
    )

    $SessionState['BoundParameterNames'] = @($PSBoundParameters.Keys | Where-Object { $global:ArmKnownParameters -contains $_ })

    # The core would write the UNREDACTED response to disk. Take ownership of the save instead.
    $requestedOutputFile = $OutputFile
    $OutputFile = $null

    # Reset from the pristine snapshot at the START of every request. A finally block
    # is not guaranteed to run when the pipeline is stopped, so restoring afterwards
    # would let a cancelled request leak its overrides into later ones.
    $Configuration['DefaultPollIntervalSeconds'] = $global:ArmPristinePoll.Default
    $Configuration['MaxPollIntervalSeconds'] = $global:ArmPristinePoll.Max
    $Configuration['LongRunningTimeoutSeconds'] = $global:ArmPristinePoll.Timeout

    if ($PSBoundParameters.ContainsKey('PollIntervalSeconds') -and $PollIntervalSeconds -gt 0) {
        $Configuration['DefaultPollIntervalSeconds'] = $PollIntervalSeconds
        if ($Configuration['MaxPollIntervalSeconds'] -lt $PollIntervalSeconds) {
            $Configuration['MaxPollIntervalSeconds'] = $PollIntervalSeconds
        }
    }
    if ($PSBoundParameters.ContainsKey('LongRunningTimeoutSeconds') -and $LongRunningTimeoutSeconds -gt 0) {
        $Configuration['LongRunningTimeoutSeconds'] = $LongRunningTimeoutSeconds
    }

    $emitted = @(Invoke-ArmRequest)
    $formatted = if ($emitted.Count -gt 0) { [string]$emitted[-1] } else { '' }
    $redactedText = ConvertTo-ArmRedactedText -Text $formatted

    $savePath = $null
    $saveError = $null
    if ($requestedOutputFile) {
        try { $savePath = Save-ArmGuiRedactedOutput -FileName $requestedOutputFile -Content $redactedText }
        catch { $saveError = $_.Exception.Message }
    }

    [pscustomobject]@{
        Raw       = $formatted
        Redacted  = $redactedText
        SavePath  = $savePath
        SaveError = $saveError
    }
}

function global:Invoke-ArmGuiSelfTest {
    $SessionState['BoundParameterNames'] = @()
    Invoke-ArmClientSelfTest
}

# Lists the 'name' of every item in an ARM collection, used to populate the
# parameter pickers. Metadata only, so it bypasses the response redaction path.
# Lists every resource of one type across the whole subscription, so a name can be
# picked without knowing its resource group first. This endpoint returns only
# top-level tracked resources; nested types fall back to their parent collection.
# Scopes an extension resource can attach to: the subscription, each resource group,
# and each resource. These are full resource IDs, not names.
function global:Get-ArmGuiScopeChoice {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId, [int]$Limit = 400)

    $subScope = '/subscriptions/' + $SubscriptionId
    [pscustomobject]@{ Id = $subScope; Name = 'This subscription'; Kind = 'Subscription'; Group = '' }

    $groupResponse = Invoke-AzRestMethod -Method GET -Path ($subScope + '/resourcegroups?api-version=2021-04-01') -ErrorAction Stop
    if ([int]$groupResponse.StatusCode -ge 200 -and [int]$groupResponse.StatusCode -lt 300) {
        $groupDocument = $groupResponse.Content | ConvertFrom-Json -ErrorAction Stop
        foreach ($item in @(Get-ObjectMemberValueSafe -InputObject $groupDocument -Name 'value')) {
            $groupName = [string](Get-ObjectMemberValueSafe -InputObject $item -Name 'name')
            if (-not $groupName) { continue }
            [pscustomobject]@{ Id = $subScope + '/resourceGroups/' + $groupName; Name = $groupName
                Kind = 'Resource group'; Group = ''
            }
        }
    }

    $emitted = 0
    $next = $subScope + '/resources?api-version=2021-04-01'
    $pages = 0
    while ($next -and $emitted -lt $Limit -and $pages -lt 20) {
        $pages++
        $response = Invoke-AzRestMethod -Method GET -Path $next -ErrorAction Stop
        if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) { break }
        $document = $response.Content | ConvertFrom-Json -ErrorAction Stop
        foreach ($item in @(Get-ObjectMemberValueSafe -InputObject $document -Name 'value')) {
            if ($emitted -ge $Limit) { break }
            $itemId = [string](Get-ObjectMemberValueSafe -InputObject $item -Name 'id')
            $itemName = [string](Get-ObjectMemberValueSafe -InputObject $item -Name 'name')
            if (-not $itemId -or -not $itemName) { continue }
            $group = ''
            if ($itemId -match '/resourceGroups/([^/]+)') { $group = $Matches[1] }
            $emitted++
            [pscustomobject]@{ Id = $itemId; Name = $itemName
                Kind = [string](Get-ObjectMemberValueSafe -InputObject $item -Name 'type'); Group = $group
            }
        }
        $link = [string](Get-ObjectMemberValueSafe -InputObject $document -Name 'nextLink')
        if ($link -and $link -match '^https?://') { $next = ([System.Uri]$link).PathAndQuery }
        elseif ($link) { $next = $link }
        else { $next = '' }
    }
}

# Every distinct resource type that actually exists in the subscription. Only the type
# is selected, and paging is followed, because a large subscription returns thousands
# of resources across many pages.
function global:Get-ArmGuiDeployedType {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $next = '/subscriptions/' + $SubscriptionId + '/resources?api-version=2021-04-01&$select=type'
    $pages = 0
    while ($next -and $pages -lt 100) {
        $pages++
        $response = Invoke-AzRestMethod -Method GET -Path $next -ErrorAction Stop
        if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
            throw ('Lookup returned status {0}.' -f $response.StatusCode)
        }
        $document = $response.Content | ConvertFrom-Json -ErrorAction Stop
        foreach ($item in @(Get-ObjectMemberValueSafe -InputObject $document -Name 'value')) {
            $armType = [string](Get-ObjectMemberValueSafe -InputObject $item -Name 'type')
            if ($armType) { $null = $seen.Add($armType) }
        }
        $link = [string](Get-ObjectMemberValueSafe -InputObject $document -Name 'nextLink')
        if ($link -and $link -match '^https?://') { $next = ([System.Uri]$link).PathAndQuery }
        elseif ($link) { $next = $link }
        else { $next = '' }
    }
    foreach ($armType in ($seen | Sort-Object)) { $armType }
}

function global:Get-ArmGuiResourceByType {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId,
        [Parameter(Mandatory = $true)][string]$ResourceType)

    $filter = [System.Uri]::EscapeDataString("resourceType eq '$ResourceType'")
    $full = '/subscriptions/' + $SubscriptionId + '/resources?$filter=' + $filter + '&api-version=2021-04-01'
    $response = Invoke-AzRestMethod -Method GET -Path $full -ErrorAction Stop
    if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
        throw ('Lookup returned status {0}.' -f $response.StatusCode)
    }
    $document = $response.Content | ConvertFrom-Json -ErrorAction Stop
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @(Get-ObjectMemberValueSafe -InputObject $document -Name 'value')) {
        $itemName = [string](Get-ObjectMemberValueSafe -InputObject $item -Name 'name')
        if (-not $itemName) { continue }
        $itemId = [string](Get-ObjectMemberValueSafe -InputObject $item -Name 'id')
        $group = ''
        if ($itemId -match '/resourceGroups/([^/]+)') { $group = $Matches[1] }
        $rows.Add([pscustomobject]@{ Name = $itemName; ResourceGroup = $group }) | Out-Null
    }
    # One per pipeline item: returning the array whole arrives at the UI as one object.
    foreach ($row in ($rows | Sort-Object Name)) { $row }
}

function global:Get-ArmGuiResourceNames {
    param([Parameter(Mandatory=$true)][string]$Path, [string]$ApiVersion = '2021-04-01')
    $full = $Path
    if ($full -notmatch '[?&]api-version=') {
        $separator = if ($full.Contains('?')) { '&' } else { '?' }
        $full = $full + $separator + 'api-version=' + $ApiVersion
    }
    $response = Invoke-AzRestMethod -Method GET -Path $full -ErrorAction Stop
    if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
        throw ('Lookup returned status {0}.' -f $response.StatusCode)
    }
    $document = $response.Content | ConvertFrom-Json -ErrorAction Stop
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(Get-ObjectMemberValueSafe -InputObject $document -Name 'value')) {
        $name = [string](Get-ObjectMemberValueSafe -InputObject $item -Name 'name')
        if ($name) { $names.Add($name) }
    }
    # Emitted one per pipeline item on purpose: returning the array as a single
    # object makes it arrive at the UI as one concatenated string.
    foreach ($name in ($names | Sort-Object)) { $name }
}

function global:Get-ArmGuiSubscriptionChoice {
    $context = Get-CurrentAzContextSafe
    $currentId = if ($null -ne $context) { [string]$context.SubscriptionId } else { '' }
    foreach ($subscription in (Get-AzSubscription -ErrorAction Stop | Sort-Object Name)) {
        [pscustomobject]@{
            Id        = [string]$subscription.Id
            Name      = [string]$subscription.Name
            State     = [string]$subscription.State
            IsCurrent = ([string]$subscription.Id -eq $currentId)
        }
    }
}

# ---------------------------------------------------------------------------
# ARM operation discovery
# ARM exposes thousands of operations, so the catalog is discovered live rather
# than hardcoded. RBAC operation names are parsed into request templates.
# ---------------------------------------------------------------------------

$global:ArmScopeOverrides = @{
    'microsoft.resources/resourcegroups'   = 'Subscription'
    'microsoft.resources/subscriptions'    = 'Tenant'
    'microsoft.resources/tenants'          = 'Tenant'
    'microsoft.resources/providers'        = 'Subscription'
    'microsoft.resources/deployments'      = 'ResourceGroup'
    'microsoft.management/managementgroups' = 'Tenant'
    'microsoft.subscription/aliases'       = 'Tenant'
    'microsoft.billing/billingaccounts'    = 'Tenant'
    'microsoft.authorization/roledefinitions' = 'Subscription'
    'microsoft.authorization/roleassignments' = 'Subscription'
}

# Resource Manager's own URI grammar reserves a fixed set of root segments that are NOT
# reached through /providers/{namespace}/. Every one is claimed by Microsoft.Resources,
# and nothing in provider metadata distinguishes them from an ordinary type, so this
# list is the only correct way to route them. Path is the collection form and Leaf is
# the name segment appended for the item form. Keys are namespace-qualified so that a
# type merely containing the token 'providers', such as Microsoft.Features/providers/
# features, cannot collide with the Microsoft.Resources/providers root.
$global:ArmDocumentedRoutes = @{
    'microsoft.resources/subscriptions'                            = @{ Scope = 'Tenant'; Path = '/subscriptions'; Leaf = 'subscriptionId' }
    'microsoft.resources/tenants'                                  = @{ Scope = 'Tenant'; Path = '/tenants'; Leaf = '' }
    'microsoft.resources/providers'                                = @{ Scope = 'Tenant'; Path = '/providers'; Leaf = 'resourceProviderNamespace' }
    'microsoft.resources/resourcegroups'                           = @{ Scope = 'Subscription'; Path = '/subscriptions/{subscriptionId}/resourcegroups'; Leaf = 'resourceGroupName' }
    'microsoft.resources/resources'                                = @{ Scope = 'Subscription'; Path = '/subscriptions/{subscriptionId}/resources'; Leaf = '' }
    'microsoft.resources/subscriptions/providers'                  = @{ Scope = 'Subscription'; Path = '/subscriptions/{subscriptionId}/providers'; Leaf = 'resourceProviderNamespace' }
    'microsoft.resources/subscriptions/resourcegroups'             = @{ Scope = 'Subscription'; Path = '/subscriptions/{subscriptionId}/resourcegroups'; Leaf = 'resourceGroupName' }
    'microsoft.resources/subscriptions/resources'                  = @{ Scope = 'Subscription'; Path = '/subscriptions/{subscriptionId}/resources'; Leaf = '' }
    'microsoft.resources/subscriptions/locations'                  = @{ Scope = 'Subscription'; Path = '/subscriptions/{subscriptionId}/locations'; Leaf = '' }
    'microsoft.resources/subscriptions/operationresults'           = @{ Scope = 'Subscription'; Path = '/subscriptions/{subscriptionId}/operationresults'; Leaf = 'operationId' }
    'microsoft.resources/subscriptions/tagnames'                   = @{ Scope = 'Subscription'; Path = '/subscriptions/{subscriptionId}/tagNames'; Leaf = 'tagName' }
    'microsoft.resources/subscriptions/tagnames/tagvalues'         = @{ Scope = 'Subscription'; Path = '/subscriptions/{subscriptionId}/tagNames/{tagName}/tagValues'; Leaf = 'tagValue' }
    'microsoft.resources/subscriptions/resourcegroups/resources'   = @{ Scope = 'ResourceGroup'; Path = '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/resources'; Leaf = '' }
    'microsoft.resources/subscriptions/resourcegroups/deployments' = @{ Scope = 'ResourceGroup'; Path = '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/Microsoft.Resources/deployments'; Leaf = 'deploymentName' }
}

# The operation names are inconsistently cased in ARM's own metadata: subscriptions/
# resourceGroups has a capital G while subscriptions/resourcegroups/resources does not.
# A PowerShell hashtable already compares keys case-insensitively, which is what makes
# both forms resolve; the lowercasing below only keeps the key readable in diagnostics.
function global:Get-ArmDocumentedRoute {
    param([Parameter(Mandatory=$true)][pscustomobject]$Parsed)
    $segments = @($Parsed.TypeSegments)
    for ($i = $segments.Count; $i -ge 1; $i--) {
        $key = ('{0}/{1}' -f $Parsed.Namespace, (@($segments[0..($i - 1)]) -join '/')).ToLowerInvariant()
        if ($global:ArmDocumentedRoutes.ContainsKey($key)) {
            return [pscustomobject]@{ Route = $global:ArmDocumentedRoutes[$key]; Depth = $i }
        }
    }
    return $null
}

function global:New-ArmDocumentedTemplate {
    param([Parameter(Mandatory=$true)][pscustomobject]$Parsed,
          [Parameter(Mandatory=$true)][object]$Match)

    $path = [string]$Match.Route.Path
    $placeholders = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($path, '\{([A-Za-z0-9]+)\}')) { $placeholders.Add($m.Groups[1].Value) }

    $tail = @(@($Parsed.TypeSegments) | Select-Object -Skip $Match.Depth)
    $leaf = [string]$Match.Route.Leaf
    # The mapped path is the collection. The item name is required for every verb except
    # a collection GET, and always once a child type follows it.
    if ($leaf -and (($tail.Count -gt 0) -or ($Parsed.Verb -ne 'read'))) {
        $path = $path + '/{' + $leaf + '}'
        $placeholders.Add($leaf)
    }

    for ($i = 0; $i -lt $tail.Count; $i++) {
        $segment = $tail[$i]
        $path = $path + '/' + $segment
        if (($i -ne ($tail.Count - 1)) -or ($Parsed.Verb -ne 'read')) {
            $name = ConvertTo-ArmPlaceholderName -Segment $segment
            $suffix = 1
            while ($placeholders.Contains($name)) { $suffix++; $name = (ConvertTo-ArmPlaceholderName -Segment $segment) + $suffix }
            $placeholders.Add($name)
            $path = $path + '/{' + $name + '}'
        }
    }
    if ($Parsed.Verb -eq 'action') { $path = $path + '/' + $Parsed.ActionName }

    [pscustomobject]@{ Template = $path; Placeholders = @($placeholders.ToArray()) }
}

# Get-LatestStableApiVersion in the core script excludes only the literal 'preview', so
# a -beta or -rc version is chosen as though it were stable.
$global:ArmPreReleasePattern = '(?i)-(preview|beta|alpha|rc\d*)'
function global:Get-ArmGuiDefaultApiVersion {
    param([string[]]$Versions)
    # Sort-ApiVersionList yields nothing for an empty list, which binds here as a single
    # null element, so empties are filtered before the count is trusted.
    $ordered = @(@($Versions) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $stable = @($ordered | Where-Object { $_ -notmatch $global:ArmPreReleasePattern })
    if ($stable.Count -gt 0) { return $stable[0] }
    if ($ordered.Count -gt 0) { return $ordered[0] }
    return $null
}

# Operations whose responses carry credentials. Derived from the operation name,
# which is far more reliable than pattern-matching a response body.
$global:ArmSecretActionPattern = '^(list(keys|secrets|credentials|connectionstrings|accountsas|servicesas|querykeys|adminkeys|sas|clusteradmincredential|clusterusercredential|serviceprincipalcredentials)|regeneratekey|regeneratecredential|listkeyvalue|getsecrets|publishingprofile|listsinglesignonurl)$'

function global:ConvertFrom-RbacOperationName {
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$OperationName)

    $parsed = [pscustomobject]@{
        OperationName = $OperationName; Namespace = $null; TypeSegments = @()
        ResourceType = $null; Verb = $null; ActionName = $null; Method = $null
        IsProviderLevel = $false; IsSupported = $false; Reason = $null
    }
    if ([string]::IsNullOrWhiteSpace($OperationName)) { $parsed.Reason = 'Empty operation name.'; return $parsed }
    if ($OperationName -match '[\*\?]') { $parsed.Reason = 'Wildcard pattern from a role definition, not a callable endpoint.'; return $parsed }

    $tokens = @($OperationName -split '/' | Where-Object { $_ -ne '' })
    if ($tokens.Count -lt 2) { $parsed.Reason = 'Fewer than two path tokens.'; return $parsed }

    $parsed.Namespace = $tokens[0]
    switch ($tokens[-1].ToLowerInvariant()) {
        'read'   { $parsed.Verb = 'read';   $parsed.Method = 'GET' }
        'write'  { $parsed.Verb = 'write';  $parsed.Method = 'PUT' }
        'delete' { $parsed.Verb = 'delete'; $parsed.Method = 'DELETE' }
        'action' { $parsed.Verb = 'action'; $parsed.Method = 'POST' }
        default  { $parsed.Reason = "Unrecognized trailing verb '$($tokens[-1])'."; return $parsed }
    }
    if ($parsed.Verb -eq 'action') {
        if ($tokens.Count -lt 3) { $parsed.Reason = 'Action operation has no action segment.'; return $parsed }
        $parsed.ActionName = $tokens[-2]
    }
    # An empty array returned from an if statement unrolls to $null on assignment,
    # so the segment list is built explicitly.
    $lastTypeIndex = if ($parsed.Verb -eq 'action') { $tokens.Count - 3 } else { $tokens.Count - 2 }
    $typeSegments = @()
    if ($lastTypeIndex -ge 1) { $typeSegments = @($tokens[1..$lastTypeIndex]) }
    $parsed.TypeSegments = $typeSegments
    $parsed.ResourceType = ($typeSegments -join '/')
    $parsed.IsProviderLevel = ($typeSegments.Count -eq 0)
    if ($parsed.IsProviderLevel -and $parsed.Verb -ne 'action') {
        $parsed.Reason = 'Provider-level read/write/delete has no addressable URL.'
        return $parsed
    }
    $parsed.IsSupported = $true
    $parsed
}

function global:ConvertTo-ArmPlaceholderName {
    param([Parameter(Mandatory=$true)][string]$Segment)
    $name = $Segment
    if ($name -cmatch '^[A-Z]') { $name = $name.Substring(0, 1).ToLowerInvariant() + $name.Substring(1) }
    # Reproduces the naming used by the curated presets: emailServices -> emailServiceName.
    if ($name -match 'ies$') { $name = $name.Substring(0, $name.Length - 3) + 'y' }
    elseif ($name -match '(ss|x|z|ch|sh)es$') { $name = $name.Substring(0, $name.Length - 2) }
    elseif ($name -match 's$') { $name = $name.Substring(0, $name.Length - 1) }
    ($name + 'Name') -replace '[^A-Za-z0-9]', ''
}

function global:Get-ArmScopeVariants {
    param([Parameter(Mandatory=$true)][pscustomobject]$Parsed,
          [AllowNull()][object]$TypeMetadata)

    $segments = @($Parsed.TypeSegments)
    $root = if ($segments.Count -gt 0) { $segments[0] } else { '' }
    $key = ('{0}/{1}' -f $Parsed.Namespace, $root).ToLowerInvariant()
    $variants = [System.Collections.Generic.List[object]]::new()

    $capabilities = ''
    $locationCount = 0
    if ($null -ne $TypeMetadata) {
        $capabilities = [string](Get-ObjectMemberValueSafe -InputObject $TypeMetadata -Name 'capabilities')
        $locationCount = @(Get-ObjectMemberValueSafe -InputObject $TypeMetadata -Name 'locations').Count
    }

    $add = {
        param($scope, $prefix, $confidence, $evidence)
        $variants.Add([pscustomobject]@{ Scope = $scope; Prefix = $prefix; Confidence = $confidence; Evidence = $evidence })
    }

    if ($capabilities -match 'SupportsExtension') {
        & $add 'Extension' '/{resourceUri}' 'Definitive' 'capabilities declares SupportsExtension, so this applies to another resource scope.'
    }
    if ($Parsed.IsProviderLevel) {
        & $add 'Subscription' '/subscriptions/{subscriptionId}' 'Definitive' 'Provider-level operations are served at subscription scope.'
    }
    elseif ($global:ArmScopeOverrides.ContainsKey($key)) {
        $scope = $global:ArmScopeOverrides[$key]
        $prefix = switch ($scope) {
            'Tenant'       { '' }
            'Subscription' { '/subscriptions/{subscriptionId}' }
            default        { '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' }
        }
        & $add $scope $prefix 'Definitive' 'Known Azure Resource Manager scope for this namespace. Confidence refers to the scope only; the rest of the path is still built from the operation name.'
    }
    elseif ($root -ieq 'operations') {
        & $add 'Tenant' '' 'High' 'The operations type is served at tenant scope.'
    }
    elseif ($root -ieq 'locations') {
        & $add 'Subscription' '/subscriptions/{subscriptionId}' 'High' 'Location-scoped types are addressed under the subscription.'
    }
    elseif ($capabilities -match 'SupportsTags|SupportsLocation') {
        & $add 'ResourceGroup' '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' 'High' 'capabilities declares SupportsTags or SupportsLocation, indicating a tracked resource-group resource.'
        & $add 'Subscription' '/subscriptions/{subscriptionId}' 'Low' 'Alternative if the type is addressed at subscription scope.'
    }
    elseif ($locationCount -gt 0) {
        & $add 'ResourceGroup' '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' 'Medium' 'The type declares deployment locations, which usually indicates a resource-group resource.'
        & $add 'Subscription' '/subscriptions/{subscriptionId}' 'Low' 'Alternative if the type is addressed at subscription scope.'
    }
    else {
        & $add 'ResourceGroup' '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' 'Low' 'Scope could not be determined from provider metadata. Verify before sending.'
        & $add 'Subscription' '/subscriptions/{subscriptionId}' 'Low' 'Scope could not be determined from provider metadata. Verify before sending.'
        & $add 'Tenant' '' 'Low' 'Scope could not be determined from provider metadata. Verify before sending.'
    }
    $variants
}

function global:New-ArmDerivedOperation {
    param([Parameter(Mandatory=$true)][pscustomobject]$Parsed,
          [AllowNull()][object]$Operation,
          [AllowNull()][object]$TypeMetadata,
          [string[]]$ApiVersions)

    $segments = [System.Collections.Generic.List[string]]::new()
    $placeholders = [System.Collections.Generic.List[string]]::new()
    $segments.Add('providers')
    $segments.Add($Parsed.Namespace)

    $typeSegments = @($Parsed.TypeSegments)
    $typeCount = $typeSegments.Count
    for ($i = 0; $i -lt $typeCount; $i++) {
        $segment = $typeSegments[$i]
        $segments.Add($segment)
        $isLeaf = ($i -eq ($typeCount - 1))
        # The leaf name is omitted for a collection GET and required everywhere else.
        if (-not $isLeaf -or $Parsed.Verb -ne 'read') {
            $placeholder = ConvertTo-ArmPlaceholderName -Segment $segment
            $suffix = 1
            while ($placeholders.Contains($placeholder)) { $suffix++; $placeholder = (ConvertTo-ArmPlaceholderName -Segment $segment) + $suffix }
            $placeholders.Add($placeholder)
            $segments.Add('{' + $placeholder + '}')
        }
    }
    if ($Parsed.Verb -eq 'action') { $segments.Add($Parsed.ActionName) }

    $documented = Get-ArmDocumentedRoute -Parsed $Parsed
    if ($null -ne $documented) {
        $built = New-ArmDocumentedTemplate -Parsed $Parsed -Match $documented
        $routeSource = 'Documented'
        $templates = @([pscustomobject]@{
                Scope = [string]$documented.Route.Scope
                Confidence = 'Definitive'
                Evidence = 'Microsoft publishes this exact URL for this operation. The path is taken from the documented request template, not inferred.'
                Template = $built.Template
                Placeholders = @($built.Placeholders)
            })
    }
    else {
        $routeSource = 'Derived'
        $variants = Get-ArmScopeVariants -Parsed $Parsed -TypeMetadata $TypeMetadata
        $tail = ($segments -join '/')
        $templates = foreach ($variant in $variants) {
            $prefix = [string]$variant.Prefix
            $template = ($prefix + '/' + $tail)
            if (-not $template.StartsWith('/')) { $template = '/' + $template }
            $extra = [System.Collections.Generic.List[string]]::new()
            foreach ($m in [regex]::Matches($prefix, '\{([A-Za-z0-9]+)\}')) { $extra.Add($m.Groups[1].Value) }
            [pscustomobject]@{
                Scope = $variant.Scope; Confidence = $variant.Confidence; Evidence = $variant.Evidence
                Template = $template; Placeholders = @(@($extra) + @($placeholders))
            }
        }
    }

    $sortedVersions = Sort-ApiVersionList -ApiVersionsToSort $ApiVersions
    $defaultVersion = Get-ArmGuiDefaultApiVersion -Versions $sortedVersions
    # Provider registration is served by the resource provider API, not the target type's.
    if ($Parsed.IsProviderLevel) { $defaultVersion = '2021-04-01'; $sortedVersions = @('2021-04-01') }

    $action = if ($Parsed.ActionName) { $Parsed.ActionName.ToLowerInvariant() } else { '' }
    $isSecret = ($action -match $global:ArmSecretActionPattern)
    $risk = switch ($Parsed.Verb) {
        'read'   { if ($isSecret) { 'Credential' } else { 'Read' } }
        'delete' { 'Destructive' }
        'write'  { 'Write' }
        default  { if ($isSecret) { 'Credential' } else { 'Action' } }
    }

    $displayName = [string](Get-ObjectMemberValueSafe -InputObject $Operation -Name 'displayName')
    $description = [string](Get-ObjectMemberValueSafe -InputObject $Operation -Name 'description')

    [pscustomobject]@{
        # Name/IsPreset/SearchBlob/ProviderNamespace/ResourceType are the contract
        # Initialize-CatalogSearchIndex consumes.
        Name = $Parsed.OperationName
        IsPreset = $false
        Method = $Parsed.Method
        Description = $description
        ProviderNamespace = $Parsed.Namespace
        ResourceType = $Parsed.ResourceType
        SearchBlob = (@(@($Parsed.OperationName, $displayName, $description, $Parsed.Method, $Parsed.Namespace, $Parsed.ResourceType) |
                    Where-Object { -not [string]::IsNullOrEmpty($_) }) -join ' ').ToUpperInvariant()
        Category = $Parsed.Namespace
        Kind = 'Discovered'
        OperationName = $Parsed.OperationName
        DisplayName = $displayName
        Origin = [string](Get-ObjectMemberValueSafe -InputObject $Operation -Name 'origin')
        ApiVersion = $defaultVersion
        ApiVersions = @($sortedVersions)
        ScopeVariants = @($templates)
        RouteSource = $routeSource
        IsSecret = $isSecret
        Risk = $risk
        HasApiVersion = (-not [string]::IsNullOrWhiteSpace($defaultVersion))
    }
}

function global:Get-ArmMetadataPage {
    param([Parameter(Mandatory=$true)][string]$Path)
    # Deliberately bypasses Invoke-ArmRequest: these payloads are tens of megabytes and
    # the redaction plus pretty-print round trip would dominate the fetch.
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Path
    $page = 0
    while ($next) {
        $page++
        Write-Log -Level 'INFO' -Message ('Fetching ARM metadata page {0}.' -f $page)
        $response = if ($next -match '^https://') { Invoke-AzRestMethod -Method GET -Uri $next -ErrorAction Stop }
        else { Invoke-AzRestMethod -Method GET -Path $next -ErrorAction Stop }
        if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
            throw ('ARM metadata request failed with status {0}.' -f $response.StatusCode)
        }
        $document = $response.Content | ConvertFrom-Json -ErrorAction Stop
        foreach ($item in @(Get-ObjectMemberValueSafe -InputObject $document -Name 'value')) { $items.Add($item) }
        $next = [string](Get-ObjectMemberValueSafe -InputObject $document -Name 'nextLink')
    }
    , $items.ToArray()
}

function global:Get-ArmGuiOperationCatalog {
    $context = Get-CurrentAzContextSafe
    if ($null -eq $context -or -not $context.SubscriptionId) { throw 'A subscription must be selected before ARM operations can be discovered.' }

    Write-Log -Level 'INFO' -Message 'Discovering resource providers.'
    $providers = Get-ArmMetadataPage -Path ('/subscriptions/{0}/providers?api-version=2021-04-01' -f $context.SubscriptionId)

    # Index resource types by namespace/type so operations can be joined to api-versions.
    $typeIndex = @{}
    foreach ($provider in $providers) {
        $namespace = [string](Get-ObjectMemberValueSafe -InputObject $provider -Name 'namespace')
        if (-not $namespace) { continue }
        foreach ($type in @(Get-ObjectMemberValueSafe -InputObject $provider -Name 'resourceTypes')) {
            $typeName = [string](Get-ObjectMemberValueSafe -InputObject $type -Name 'resourceType')
            if (-not $typeName) { continue }
            $typeIndex[('{0}/{1}' -f $namespace, $typeName).ToLowerInvariant()] = $type
        }
    }
    Write-Log -Level 'INFO' -Message ('Indexed {0} resource types from {1} providers.' -f $typeIndex.Count, $providers.Count)

    Write-Log -Level 'INFO' -Message 'Discovering provider operations.'
    $metadata = Get-ArmMetadataPage -Path '/providers/Microsoft.Authorization/providerOperations?api-version=2022-04-01&$expand=resourceTypes'

    $derived = [System.Collections.Generic.List[object]]::new()
    $skipped = 0
    $dataActions = 0
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($providerMeta in $metadata) {
        $operationSets = [System.Collections.Generic.List[object]]::new()
        foreach ($op in @(Get-ObjectMemberValueSafe -InputObject $providerMeta -Name 'operations')) { $operationSets.Add($op) }
        foreach ($type in @(Get-ObjectMemberValueSafe -InputObject $providerMeta -Name 'resourceTypes')) {
            foreach ($op in @(Get-ObjectMemberValueSafe -InputObject $type -Name 'operations')) { $operationSets.Add($op) }
        }
        foreach ($operation in $operationSets) {
            $name = [string](Get-ObjectMemberValueSafe -InputObject $operation -Name 'name')
            if (-not $name -or -not $seen.Add($name)) { continue }
            # Data actions are served by the resource's own endpoint, never by ARM.
            if ([bool](Get-ObjectMemberValueSafe -InputObject $operation -Name 'isDataAction')) { $dataActions++; continue }

            $parsed = ConvertFrom-RbacOperationName -OperationName $name
            if (-not $parsed.IsSupported) { $skipped++; continue }

            $typeMetadata = $null
            $lookup = ('{0}/{1}' -f $parsed.Namespace, $parsed.ResourceType).ToLowerInvariant()
            if ($typeIndex.ContainsKey($lookup)) { $typeMetadata = $typeIndex[$lookup] }
            $versions = @()
            if ($null -ne $typeMetadata) { $versions = @(Get-ObjectMemberValueSafe -InputObject $typeMetadata -Name 'apiVersions') }

            $derived.Add((New-ArmDerivedOperation -Parsed $parsed -Operation $operation -TypeMetadata $typeMetadata -ApiVersions $versions))
        }
    }

    Write-Log -Level 'INFO' -Message ('Derived {0} callable operations. Excluded {1} data-plane actions and {2} unmappable entries.' -f $derived.Count, $dataActions, $skipped)
    [pscustomobject]@{
        Operations   = $derived.ToArray()
        ProviderCount = $providers.Count
        TypeCount    = $typeIndex.Count
        DataActions  = $dataActions
        Skipped      = $skipped
        SubscriptionId = [string]$context.SubscriptionId
        TenantId     = [string]$context.TenantId
        FetchedUtc   = (Get-Date).ToUniversalTime().ToString('o')
    }
}

'READY'
'@

function Start-Worker {
    $rs = [runspacefactory]::CreateRunspace()
    try { $rs.ApartmentState = 'STA' } catch { }
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()
    $script:App.Runspace = $rs

    $ps = [PowerShell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript($WorkerBootstrap).AddArgument($script:App.ScriptPath)
    $result = $ps.Invoke()
    if ($ps.Streams.Error.Count -gt 0) {
        $message = ($ps.Streams.Error | ForEach-Object { $_.Exception.Message }) -join [Environment]::NewLine
        $ps.Dispose()
        throw "ArmClient-PS could not be loaded.`r`n`r`n$message"
    }
    $ps.Dispose()
    if (@($result) -notcontains 'READY') { throw 'The ArmClient-PS worker did not report readiness.' }
}

function Invoke-Worker {
    param(
        [Parameter(Mandatory = $true)][string]$Script,
        [hashtable]$Parameters = @{},
        [Parameter(Mandatory = $true)][scriptblock]$OnSuccess,
        [scriptblock]$OnFailure,
        [string]$StatusText = 'Working'
    )
    if ($script:App.Busy) { return }

    $ps = [PowerShell]::Create()
    $ps.Runspace = $script:App.Runspace
    $null = $ps.AddScript($Script)
    foreach ($key in $Parameters.Keys) { $null = $ps.AddParameter($key, $Parameters[$key]) }

    $script:App.Worker = $ps
    $script:App.InfoIndex = 0
    $script:App.WarnIndex = 0
    $script:App.ErrorIndex = 0
    $script:App.Started = Get-Date
    $script:App.LastStatusSecond = -1
    $script:App.OnSuccess = $OnSuccess
    $script:App.OnFailure = $OnFailure

    Set-Busy -IsBusy $true -Kind $StatusText
    Set-Status $StatusText
    $script:App.WorkerAsync = $ps.BeginInvoke()
    $script:App.Pump.Start()
}

function Stop-Worker {
    if ($null -ne $script:App.Worker) {
        Set-Status 'Cancelling'
        try { $script:App.Worker.Stop() } catch { }
    }
}

# ==============================================================================
# REGION 10  Dispatcher pump
# Streams are drained on the UI thread, which avoids invoking a scriptblock on a
# runspace that is still executing a pipeline.
# ==============================================================================

function Complete-Worker {
    $ps = $script:App.Worker
    if ($null -eq $ps) { return }

    $script:App.Pump.Stop()
    # Drain whatever arrived since the last tick, otherwise the final log lines are lost.
    Read-WorkerStreams -Worker $ps

    $output = $null
    $failure = $null
    try { $output = $ps.EndInvoke($script:App.WorkerAsync) }
    catch { $failure = $_.Exception.Message }

    $stopped = ($ps.InvocationStateInfo.State -eq 'Stopped')
    if (-not $stopped) {
        while ($script:App.ErrorIndex -lt $ps.Streams.Error.Count) {
            $record = $ps.Streams.Error[$script:App.ErrorIndex]
            $script:App.ErrorIndex++
            if ($null -eq $failure) { $failure = $record.Exception.Message }
            Add-LogLine ('ERROR ' + (ConvertTo-SafeErrorText $record.Exception.Message))
        }
    }

    $onSuccess = $script:App.OnSuccess
    $onFailure = $script:App.OnFailure
    $ps.Dispose()
    $script:App.Worker = $null
    $script:App.WorkerAsync = $null
    $script:App.OnSuccess = $null
    $script:App.OnFailure = $null

    $elapsed = (Get-Date) - $script:App.Started
    $ui.TxtElapsed.Text = ('{0:n1} s' -f $elapsed.TotalSeconds)
    Set-Busy -IsBusy $false
    Write-LogBuffer

    if ($stopped) {
        Set-Status 'Cancelled' -Kind 'Problem'
        Add-LogLine 'The operation was cancelled.'
        return
    }
    if ($null -ne $failure) {
        Set-Status 'Failed' -Kind 'Problem'
        if ($null -ne $onFailure) { & $onFailure $failure }
        else { Show-Message -Text (Get-FriendlyFailureText -Message $failure) -Caption 'Operation failed' -Icon 'Error' }
        return
    }
    if ($null -ne $onSuccess) { & $onSuccess @($output) }
}

# Tears down a worker whose pipeline state is no longer trustworthy so a later
# request cannot run concurrently against the same shared session state.
function Reset-Worker {
    try { if ($null -ne $script:App.Pump) { $script:App.Pump.Stop() } } catch { }
    Write-LogBuffer
    $ps = $script:App.Worker
    $script:App.Worker = $null
    $script:App.WorkerAsync = $null
    $script:App.OnSuccess = $null
    $script:App.OnFailure = $null
    if ($null -ne $ps) {
        # Dispose performs a synchronous Stop anyway, so call it explicitly rather
        # than implying this is non-blocking.
        try { $ps.Stop() } catch { }
        try { $ps.Dispose() } catch { }
    }
    Set-Busy -IsBusy $false
}

function Read-WorkerStreams {
    param([Parameter(Mandatory = $true)][object]$Worker)
    $info = $Worker.Streams.Information
    while ($script:App.InfoIndex -lt $info.Count) {
        $record = $info[$script:App.InfoIndex]
        $script:App.InfoIndex++
        Add-LogLine ([string]$record.MessageData)
    }
    $warn = $Worker.Streams.Warning
    while ($script:App.WarnIndex -lt $warn.Count) {
        $record = $warn[$script:App.WarnIndex]
        $script:App.WarnIndex++
        Add-LogLine ('WARN ' + (ConvertTo-SafeErrorText $record.Message))
    }
}

function Initialize-Pump {
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(120)
    $timer.Add_Tick({
            try {
                $ps = $script:App.Worker
                if ($null -eq $ps) { $script:App.Pump.Stop(); return }

                Read-WorkerStreams -Worker $ps
                Write-LogBuffer

                if ($script:App.Busy -and $null -ne $script:App.Started) {
                    $seconds = [int]((Get-Date) - $script:App.Started).TotalSeconds
                    if ($seconds -ne $script:App.LastStatusSecond) {
                        $script:App.LastStatusSecond = $seconds
                        # The status bar owns the live counter. TxtElapsed shows the final
                        # duration only, so it is not written while the request is running.
                        Set-Status ('{0} ... {1}s' -f $script:App.Kind, $seconds)
                    }
                }

                if ($script:App.WorkerAsync.IsCompleted) { Complete-Worker }
            }
            catch {
                # The pipeline state is unknown at this point, so tear the worker down
                # rather than leaving it running against shared session state.
                Reset-Worker
                Show-Message -Text (ConvertTo-SafeErrorText $_.Exception.Message) -Caption 'Internal error' -Icon 'Error'
            }
        })
    $script:App.Pump = $timer
}

# ==============================================================================
# REGION 11  Safe text
# ==============================================================================

function ConvertTo-SafeErrorText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return 'An unspecified error occurred.' }
    $safe = $Text
    $safe = [regex]::Replace($safe, '(?i)(Authorization\s*[:=]\s*)(Bearer\s+)?[^\r\n;]+', '$1[REDACTED]')
    $safe = [regex]::Replace($safe, '(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*', '[REDACTED JWT]')
    $safe = [regex]::Replace($safe, '(?i)Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer [REDACTED]')
    $safe = [regex]::Replace($safe, '(?i)([?&](sig|sas|code|access_token|refresh_token|id_token|key)=)[^&\s]+', '$1[REDACTED]')
    if ($safe.Length -gt 4000) { $safe = $safe.Substring(0, 4000) + [Environment]::NewLine + '... truncated ...' }
    return $safe
}

# Turns the known unrecoverable failures into guidance the user can act on.
function Get-FriendlyFailureText {
    param([AllowNull()][string]$Message)
    $safe = ConvertTo-SafeErrorText -Text $Message
    if ($safe -match 'already loaded') {
        return ("Another version of Az.Accounts was already loaded in this process, so the bundled version could not be used." +
            "`r`n`r`nAz binds its assemblies once per process and cannot swap versions." +
            "`r`n`r`nClose this window and start the tool from a clean session:" +
            "`r`n    pwsh -NoProfile -File .\ArmClient-PS.Gui.ps1" +
            "`r`n`r`nTechnical detail:`r`n" + $safe)
    }
    return $safe
}

function Set-ResponseText {
    param([string]$Text)
    $display = $Text
    $suffix = ''
    if ($null -ne $display -and $display.Length -gt $script:MaxRenderChars) {
        $display = $display.Substring(0, $script:MaxRenderChars)
        $suffix = [Environment]::NewLine + ('... display truncated at {0:n0} characters. Use Save to write the full response to disk ...' -f $script:MaxRenderChars)
    }
    $ui.TxtResponse.Text = $display + $suffix
    $ui.TxtResponseEmpty.Visibility = if ([string]::IsNullOrEmpty($ui.TxtResponse.Text)) { 'Visible' } else { 'Collapsed' }
}

# ==============================================================================
# REGION 12  Catalog
# ==============================================================================

# WPF binding ignores public FIELDS and renders them empty without raising, so every
# bound member below is a property. No WPF type is named, so this compiles with no
# -ReferencedAssemblies on both hosts (PresentationCore/WindowsBase resolve to
# different versions on .NET 10 and the reference form fails with CS1705).
# C# 5 only: Windows PowerShell 5.1 compiles this with the CodeDom provider.
if (-not ('ArmGui.CatalogNode' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace ArmGui
{
    public class CatalogNode : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        // ---- bound by Catalog.Node / Catalog.NodeContainer ----
        public string Label { get; set; }
        public string Method { get; set; }
        public object MethodBrush { get; set; }
        public string CountText { get; set; }
        public string Tip { get; set; }
        public string AutomationName { get; set; }
        public bool IsGroup { get; set; }
        public object Children { get; set; }

        // ---- PowerShell only, never bound ----
        public string Kind { get; set; }
        public object Payload { get; set; }

        private bool _isExpanded;
        public bool IsExpanded
        {
            get { return _isExpanded; }
            set
            {
                if (_isExpanded == value) { return; }
                _isExpanded = value;
                PropertyChangedEventHandler h = PropertyChanged;
                if (h != null) { h(this, new PropertyChangedEventArgs("IsExpanded")); }
            }
        }

        // One call per row. Assigning these properties individually from PowerShell
        // measured 22.2 ms vs 1.2 ms for 500 rows on 5.1.
        public static CatalogNode Leaf(string kind, string label, string method, object brush, string tip, object payload)
        {
            CatalogNode n = new CatalogNode();
            n.Kind = kind;
            n.Label = label;
            n.Method = (method == null) ? "" : method;
            n.MethodBrush = brush;
            n.Tip = tip;
            n.Payload = payload;
            n.IsGroup = false;
            n.AutomationName = label + ", " + n.Method;
            return n;
        }

        public static CatalogNode Group(string label, string countText, object children, int childCount, bool expanded)
        {
            CatalogNode n = new CatalogNode();
            n.Kind = "Group";
            n.Label = label;
            n.Method = "";              // "" not null, or the chip DataTrigger never matches
            n.CountText = countText;
            n.Children = children;
            n.IsGroup = true;
            n.IsExpanded = expanded;
            n.AutomationName = label + ", " + childCount.ToString() + " items";
            return n;
        }

        public static CatalogNode Info(string label)
        {
            CatalogNode n = new CatalogNode();
            n.Kind = "Info";
            n.Label = label;
            n.Method = "";
            n.AutomationName = label;
            return n;
        }
    }

    public static class Search
    {
        // Same loop in interpreted PowerShell measured 43 ms (5.1) / 111 ms (7.6.4)
        // over 24,554 blobs; here it is 2.3 ms / 0.6 ms. Passing a candidate set
        // restricts the scan to the previous hits for an incremental narrow.
        public static int Scan(string[] blobs, string[] tokens, int[] hits, int[] candidates, int candidateCount)
        {
            int w = 0;
            int n = (candidates == null) ? blobs.Length : candidateCount;
            for (int h = 0; h < n; h++)
            {
                int i = (candidates == null) ? h : candidates[h];
                string b = blobs[i];
                bool ok = true;
                for (int t = 0; t < tokens.Length; t++)
                {
                    if (b.IndexOf(tokens[t], StringComparison.Ordinal) < 0) { ok = false; break; }
                }
                if (ok) { hits[w] = i; w++; }
            }
            return w;
        }

        // Earliest match position first, then name. Operations are stored in name
        // order, so the item index doubles as the tie-break key and the whole sort
        // stays on primitives. Ranking here also avoids Array::Sort(string[], object[])
        // from PowerShell, which sorts the keys and silently leaves the values
        // unsorted on both hosts.
        public static int[] Rank(string[] blobs, int[] hits, int count, string first, int cap)
        {
            long[] keys = new long[count];
            int[] idx = new int[count];
            for (int r = 0; r < count; r++)
            {
                int i = hits[r];
                int pos = (first.Length == 0) ? 0 : blobs[i].IndexOf(first, StringComparison.Ordinal);
                if (pos < 0) { pos = int.MaxValue; }
                keys[r] = ((long)pos << 32) | (uint)i;
                idx[r] = i;
            }
            Array.Sort(keys, idx);
            int take = (count < cap) ? count : cap;
            int[] result = new int[take];
            Array.Copy(idx, result, take);
            return result;
        }

        public static int[] NameOrder(string[] namesUpper)
        {
            int n = namesUpper.Length;
            string[] keys = (string[])namesUpper.Clone();
            int[] order = new int[n];
            for (int i = 0; i < n; i++) { order[i] = i; }
            Array.Sort(keys, order, StringComparer.Ordinal);
            return order;
        }

        public static string[] ReorderStrings(string[] source, int[] order)
        {
            string[] result = new string[order.Length];
            for (int i = 0; i < order.Length; i++) { result[i] = source[order[i]]; }
            return result;
        }

        public static object[] ReorderObjects(object[] source, int[] order)
        {
            object[] result = new object[order.Length];
            for (int i = 0; i < order.Length; i++) { result[i] = source[order[i]]; }
            return result;
        }
    }
}
'@
}

$script:SearchResultCap = 500
$script:SearchDebounceMs = 80
$script:MethodBrushes = @{}

function Get-MethodBrush {
    param([AllowNull()][string]$Method)
    $key = ''
    if ($null -ne $Method) { $key = $Method.ToUpperInvariant() }
    if ($script:MethodBrushes.ContainsKey($key)) { return $script:MethodBrushes[$key] }
    $hex = $script:MethodColors[$key]
    if (-not $hex) { $hex = '#0078D4' }
    $brush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($hex))
    $brush.Freeze()     # shared across every row instead of one brush per node
    $script:MethodBrushes[$key] = $brush
    return $brush
}

function Get-CatalogSearchBlob {
    param([Parameter(Mandatory = $true)][object]$Item)
    $blob = [string](Get-SafeProperty -InputObject $Item -Name 'SearchBlob')
    if (-not [string]::IsNullOrEmpty($blob)) { return $blob }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @('Name', 'Category', 'Description', 'Method', 'RelativePathTemplate', 'ProviderNamespace', 'ResourceType')) {
        $value = [string](Get-SafeProperty -InputObject $Item -Name $name)
        if (-not [string]::IsNullOrEmpty($value)) { $parts.Add($value) }
    }
    $aliases = @(Get-SafeProperty -InputObject $Item -Name 'Aliases')
    if ($aliases.Count -gt 0) { $parts.Add(($aliases -join ' ')) }
    return ($parts -join ' ').ToUpperInvariant()
}

# Splits the catalog once into curated presets and discovered operations, and
# precomputes the parallel uppercased arrays the hot path scans.
# Control-plane namespaces that are relevant whether or not anything is deployed:
# they manage the subscription itself rather than a deployed resource type.
$script:ArmAlwaysRelevantNamespaces = @(
    'microsoft.resources', 'microsoft.authorization', 'microsoft.management',
    'microsoft.billing', 'microsoft.subscription', 'microsoft.consumption',
    'microsoft.costmanagement', 'microsoft.advisor', 'microsoft.resourcehealth',
    'microsoft.features', 'microsoft.policyinsights', 'microsoft.support'
)

# The subscription-wide resources endpoint returns only top-level types, so a nested
# operation is judged by its parent: having an email service makes its domain
# operations relevant too.
function Test-OperationIsDeployed {
    param([Parameter(Mandatory = $true)][object]$Operation,
        [Parameter(Mandatory = $true)][object]$DeployedTypes)

    $provider = [string]$Operation.ProviderNamespace
    if ([string]::IsNullOrWhiteSpace($provider)) {
        $name = [string]$Operation.Name
        if ($name.Contains('/')) { $provider = ($name -split '/')[0] }
    }
    if ([string]::IsNullOrWhiteSpace($provider)) { return $true }

    $providerKey = $provider.ToLowerInvariant()
    if ($script:ArmAlwaysRelevantNamespaces -contains $providerKey) { return $true }

    $resourceType = [string]$Operation.ResourceType
    if ([string]::IsNullOrWhiteSpace($resourceType)) {
        # Most extended presets carry no ResourceType, but every operation has a path,
        # and the segment after the provider is the top-level type.
        $template = [string]$Operation.RelativePathTemplate
        $marker = '/providers/' + $provider + '/'
        $at = $template.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase)
        if ($at -ge 0) {
            $rest = $template.Substring($at + $marker.Length)
            $firstFromPath = @($rest -split '/' | Where-Object { $_ })[0]
            if ($firstFromPath -and $firstFromPath -notmatch '^\{.*\}$') { $resourceType = $firstFromPath }
        }
    }
    if ([string]::IsNullOrWhiteSpace($resourceType)) {
        # A provider-level operation such as register: relevant if anything from that
        # provider exists.
        foreach ($deployed in $DeployedTypes) {
            if (([string]$deployed).StartsWith($providerKey + '/', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    }

    $firstSegment = @($resourceType -split '/' | Where-Object { $_ })[0]
    if (-not $firstSegment) { return $false }
    # Both sides are lower-cased, so matching does not depend on the comparer the
    # caller happened to build the collection with.
    return $DeployedTypes.Contains($providerKey + '/' + $firstSegment.ToLowerInvariant())
}

# The catalog the tree and the search index are both built from.
function Get-RelevantCatalog {
    $catalog = @($script:App.Catalog)
    if (-not $script:App.DeployedOnly) { return $catalog }
    $deployed = $script:App.DeployedTypes
    if ($null -eq $deployed -or $deployed.Count -eq 0) { return $catalog }
    return @($catalog | Where-Object { Test-OperationIsDeployed -Operation $_ -DeployedTypes $deployed })
}

# Rebuilds the index and the tree from whatever the filter currently allows.
function Update-CatalogView {
    $relevant = @(Get-RelevantCatalog)
    Initialize-CatalogSearchIndex -Catalog $relevant
    Build-CatalogTree -Filter ([string]$ui.TxtSearch.Text)
    return $relevant.Count
}

function Initialize-CatalogSearchIndex {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Catalog)

    $presets = [System.Collections.Generic.List[object]]::new()
    $operations = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Catalog) {
        if ($item.IsPreset -eq $false) { $operations.Add($item) }
        else { $presets.Add($item) }
    }

    $count = $operations.Count
    $blobs = [string[]]::new($count)
    $namesUpper = [string[]]::new($count)
    $labels = [string[]]::new($count)
    $methods = [string[]]::new($count)
    $tips = [string[]]::new($count)
    $brushes = [object[]]::new($count)
    for ($i = 0; $i -lt $count; $i++) {
        $item = $operations[$i]
        # Direct member access, not Get-SafeProperty: a helper call per property per
        # item dominates this loop at 24k. No StrictMode is set, so a missing member
        # yields $null rather than throwing.
        $blob = [string]$item.SearchBlob
        if ([string]::IsNullOrEmpty($blob)) { $blob = Get-CatalogSearchBlob -Item $item }
        $blobs[$i] = $blob
        $label = [string]$item.Name
        $labels[$i] = $label
        $namesUpper[$i] = $label.ToUpperInvariant()
        # Everything a row renders is resolved once here, so building rows later is
        # array reads only: 500 rows cost 1,500 PSObject lookups otherwise.
        $method = [string]$item.Method
        $methods[$i] = $method
        $tips[$i] = [string]$item.Description
        $brushes[$i] = Get-MethodBrush -Method $method
    }

    # Stored in name order so Rank can tie-break on the item index and keep its sort
    # on primitive keys.
    $order = [ArmGui.Search]::NameOrder($namesUpper)
    $script:App.OpItems = [ArmGui.Search]::ReorderObjects($operations.ToArray(), $order)
    $script:App.OpBlobs = [ArmGui.Search]::ReorderStrings($blobs, $order)
    $script:App.OpNamesUpper = [ArmGui.Search]::ReorderStrings($namesUpper, $order)
    $script:App.OpLabels = [ArmGui.Search]::ReorderStrings($labels, $order)
    $script:App.OpMethods = [ArmGui.Search]::ReorderStrings($methods, $order)
    $script:App.OpTips = [ArmGui.Search]::ReorderStrings($tips, $order)
    $script:App.OpBrushes = [ArmGui.Search]::ReorderObjects($brushes, $order)

    $script:App.PresetItems = $presets.ToArray()
    $script:App.HitBuf = [int[]]::new([Math]::Max(1, $count))
    $script:App.LastHits = [int[]]::new([Math]::Max(1, $count))
    $script:App.LastHitCount = -1
    $script:App.LastTokens = [string[]]@()
    $script:App.BrowseRoots = $null

    # Presets are matched linearly every keystroke, so cache their blobs too.
    $presetBlobs = [string[]]::new($presets.Count)
    for ($i = 0; $i -lt $presets.Count; $i++) { $presetBlobs[$i] = Get-CatalogSearchBlob -Item $presets[$i] }
    $script:App.PresetBlobs = $presetBlobs
}

# Uppercase, trim, collapse internal whitespace, split. Every token must match.
function Get-SearchToken {
    param([AllowNull()][string]$Filter)
    # Unary comma on every return: PowerShell unrolls a returned collection, which
    # would hand back object[] (or $null when empty) instead of string[].
    if ([string]::IsNullOrWhiteSpace($Filter)) { return , [string[]]@() }
    $upper = $Filter.ToUpperInvariant().Trim()
    $builder = [System.Text.StringBuilder]::new($upper.Length)
    $wasSpace = $false
    for ($i = 0; $i -lt $upper.Length; $i++) {
        $char = $upper[$i]
        if ([char]::IsWhiteSpace($char)) {
            if (-not $wasSpace) { [void]$builder.Append(' ') }
            $wasSpace = $true
        }
        else {
            [void]$builder.Append($char)
            $wasSpace = $false
        }
    }
    return , [string[]]$builder.ToString().Split(@(' '), [System.StringSplitOptions]::RemoveEmptyEntries)
}

# Narrowing is sound only when every previous token is a prefix of the token now in
# the same position, because a blob containing the longer token must contain its
# prefix. Backspacing or editing an earlier token weakens the filter and must rescan,
# otherwise rows that should reappear stay hidden.
function Test-TokenNarrow {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$OldTokens,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$NewTokens
    )
    if ($OldTokens.Length -lt 1) { return $false }
    if ($NewTokens.Length -lt $OldTokens.Length) { return $false }
    for ($i = 0; $i -lt $OldTokens.Length; $i++) {
        if (-not $NewTokens[$i].StartsWith($OldTokens[$i], [System.StringComparison]::Ordinal)) { return $false }
    }
    return $true
}

function Get-CatalogMatch {
    param([Parameter(Mandatory = $true)][string[]]$Tokens)

    $blobs = $script:App.OpBlobs
    if ($blobs.Length -eq 0) { return 0 }

    $candidates = $null
    $candidateCount = 0
    if ($script:App.LastHitCount -ge 0 -and (Test-TokenNarrow -OldTokens $script:App.LastTokens -NewTokens $Tokens)) {
        $candidates = $script:App.LastHits
        $candidateCount = $script:App.LastHitCount
    }

    $count = [ArmGui.Search]::Scan($blobs, $Tokens, $script:App.HitBuf, $candidates, $candidateCount)
    [Array]::Copy($script:App.HitBuf, $script:App.LastHits, $count)
    $script:App.LastHitCount = $count
    $script:App.LastTokens = $Tokens
    return $count
}

function New-PresetGroupNode {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Tokens)

    $presets = $script:App.PresetItems
    $blobs = $script:App.PresetBlobs
    $byCategory = @{}
    $ordinal = [System.StringComparison]::Ordinal

    for ($i = 0; $i -lt $presets.Length; $i++) {
        if ($Tokens.Length -gt 0) {
            $blob = $blobs[$i]
            $matched = $true
            for ($t = 0; $t -lt $Tokens.Length; $t++) {
                if ($blob.IndexOf($Tokens[$t], $ordinal) -lt 0) { $matched = $false; break }
            }
            if (-not $matched) { continue }
        }
        $preset = $presets[$i]
        $category = [string](Get-SafeProperty -InputObject $preset -Name 'Category')
        if ([string]::IsNullOrEmpty($category)) { $category = 'Presets' }
        if (-not $byCategory.ContainsKey($category)) {
            $byCategory[$category] = [System.Collections.Generic.List[ArmGui.CatalogNode]]::new()
        }
        $method = [string](Get-SafeProperty -InputObject $preset -Name 'Method')
        $byCategory[$category].Add([ArmGui.CatalogNode]::Leaf(
                'Preset',
                [string](Get-SafeProperty -InputObject $preset -Name 'Name'),
                $method,
                (Get-MethodBrush -Method $method),
                [string](Get-SafeProperty -InputObject $preset -Name 'Description'),
                $preset))
    }

    $groups = [System.Collections.Generic.List[ArmGui.CatalogNode]]::new()
    $categories = [string[]]@($byCategory.Keys)
    [Array]::Sort($categories, [StringComparer]::OrdinalIgnoreCase)
    foreach ($category in $categories) {
        $children = $byCategory[$category]
        $groups.Add([ArmGui.CatalogNode]::Group($category, [string]$children.Count, $children, $children.Count, $true))
    }
    return , $groups
}

function New-OperationResultNode {
    param(
        [Parameter(Mandatory = $true)][int]$HitCount,
        [Parameter(Mandatory = $true)][string[]]$Tokens
    )

    $first = ''
    if ($Tokens.Length -gt 0) { $first = $Tokens[0] }
    $order = [ArmGui.Search]::Rank($script:App.OpBlobs, $script:App.HitBuf, $HitCount, $first, $script:SearchResultCap)

    $operations = $script:App.OpItems
    $labels = $script:App.OpLabels
    $methods = $script:App.OpMethods
    $tips = $script:App.OpTips
    $brushes = $script:App.OpBrushes
    $children = [System.Collections.Generic.List[ArmGui.CatalogNode]]::new($order.Length)
    for ($i = 0; $i -lt $order.Length; $i++) {
        $index = $order[$i]
        $children.Add([ArmGui.CatalogNode]::Leaf(
                'Operation', $labels[$index], $methods[$index], $brushes[$index], $tips[$index], $operations[$index]))
    }

    $countText = [string]$HitCount
    if ($HitCount -gt $order.Length) { $countText = '{0:n0}, showing {1}' -f $HitCount, $order.Length }
    return [ArmGui.CatalogNode]::Group('Matching operations', $countText, $children, $HitCount, $true)
}

# Unfiltered, the discovered set is grouped namespace -> resourceType and built once,
# because rebuilding thousands of nodes on every clear of the search box is pure waste.
function Get-BrowseRootNode {
    if ($null -ne $script:App.BrowseRoots) { return , $script:App.BrowseRoots }

    $operations = $script:App.OpItems
    $roots = [System.Collections.Generic.List[ArmGui.CatalogNode]]::new()
    if ($operations.Length -gt 0) {
        $labels = $script:App.OpLabels
        $methods = $script:App.OpMethods
        $tips = $script:App.OpTips
        $brushes = $script:App.OpBrushes
        $byNamespace = @{}
        for ($i = 0; $i -lt $operations.Length; $i++) {
            $operation = $operations[$i]
            $namespaceName = [string]$operation.ProviderNamespace
            if ([string]::IsNullOrEmpty($namespaceName)) { $namespaceName = 'Other' }
            $resourceType = [string]$operation.ResourceType
            if ([string]::IsNullOrEmpty($resourceType)) { $resourceType = 'Other' }
            if (-not $byNamespace.ContainsKey($namespaceName)) { $byNamespace[$namespaceName] = @{} }
            $byType = $byNamespace[$namespaceName]
            if (-not $byType.ContainsKey($resourceType)) {
                $byType[$resourceType] = [System.Collections.Generic.List[ArmGui.CatalogNode]]::new()
            }
            $byType[$resourceType].Add([ArmGui.CatalogNode]::Leaf(
                    'Operation', $labels[$i], $methods[$i], $brushes[$i], $tips[$i], $operation))
        }

        $namespaceNames = [string[]]@($byNamespace.Keys)
        [Array]::Sort($namespaceNames, [StringComparer]::OrdinalIgnoreCase)
        foreach ($namespaceName in $namespaceNames) {
            $byType = $byNamespace[$namespaceName]
            $typeNames = [string[]]@($byType.Keys)
            [Array]::Sort($typeNames, [StringComparer]::OrdinalIgnoreCase)
            $typeNodes = [System.Collections.Generic.List[ArmGui.CatalogNode]]::new($typeNames.Length)
            $total = 0
            foreach ($typeName in $typeNames) {
                $leaves = $byType[$typeName]
                $total += $leaves.Count
                $typeNodes.Add([ArmGui.CatalogNode]::Group($typeName, [string]$leaves.Count, $leaves, $leaves.Count, $false))
            }
            $roots.Add([ArmGui.CatalogNode]::Group($namespaceName, [string]$total, $typeNodes, $total, $false))
        }
    }

    $script:App.BrowseRoots = $roots
    return , $roots
}

function Build-CatalogTree {
    param([string]$Filter = '')

    $tokens = Get-SearchToken -Filter $Filter
    $roots = New-PresetGroupNode -Tokens $tokens

    if ($tokens.Length -eq 0) {
        $script:App.LastHitCount = -1
        $script:App.LastTokens = [string[]]@()
        foreach ($node in (Get-BrowseRootNode)) { $roots.Add($node) }
    }
    elseif ($script:App.OpBlobs.Length -gt 0) {
        $hitCount = Get-CatalogMatch -Tokens $tokens
        if ($hitCount -gt 0) { $roots.Add((New-OperationResultNode -HitCount $hitCount -Tokens $tokens)) }
    }

    if ($roots.Count -eq 0) { $roots.Add([ArmGui.CatalogNode]::Info('No operations match the filter.')) }

    # Assigned directly. Nulling ItemsSource first measured +15 ms (5.1) / +33 ms
    # (7.6.4) and defeats container recycling.
    $ui.TreeCatalog.ItemsSource = $roots
}

# Example values for the placeholders Resource Manager's own URI grammar defines. These
# feed the hint on each parameter box. Nothing in provider metadata carries a request
# schema, so bodies are only offered for routes whose shape is published.
$script:ArmPlaceholderExamples = @{
    subscriptionId            = '00000000-0000-0000-0000-000000000000'
    resourceGroupName         = 'rg-contoso-prod'
    resourceProviderNamespace = 'Microsoft.Compute'
    location                  = 'eastus'
    tagName                   = 'costCenter'
    tagValue                  = 'finance-1042'
    operationId               = '00000000-0000-0000-0000-000000000000'
    deploymentName            = 'contoso-deployment'
    managementGroupName       = 'mg-contoso'
    resourceUri               = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-contoso-prod/providers/Microsoft.Storage/storageAccounts/contosostorage'
}

$script:ArmDocumentedExampleBodies = @{
    'microsoft.resources/subscriptions/resourcegroups/write' = "{`r`n  `"location`": `"eastus`",`r`n  `"tags`": {`r`n    `"costCenter`": `"finance-1042`"`r`n  }`r`n}"
    'microsoft.resources/resourcegroups/write'               = "{`r`n  `"location`": `"eastus`",`r`n  `"tags`": {`r`n    `"costCenter`": `"finance-1042`"`r`n  }`r`n}"
    'microsoft.resources/subscriptions/tagnames/tagvalues/write' = "{`r`n  `"tagValue`": `"finance-1042`"`r`n}"
}

# A discovered operation is projected into the shape the preset pane and the request
# pipeline already consume. Source is 'Extended' so Build-RequestArguments resolves it
# by path rather than by -Operation, which the core only honours for its own catalog.
function New-DiscoveredProjection {
    param([Parameter(Mandatory = $true)][object]$Operation, [Parameter(Mandatory = $true)][string]$Template)
    $method = [string](Get-SafeProperty -InputObject $Operation -Name 'Method')
    if (-not $method) { $method = 'GET' }
    $required = @(Get-PresetPlaceholders -Template $Template)
    $name = [string](Get-SafeProperty -InputObject $Operation -Name 'Name')

    $examples = @{}
    foreach ($placeholder in $required) {
        if ($script:ArmPlaceholderExamples.ContainsKey($placeholder)) {
            $examples[$placeholder] = [string]$script:ArmPlaceholderExamples[$placeholder]
        }
    }
    $body = ''
    $bodyKey = $name.ToLowerInvariant()
    if ($script:ArmDocumentedExampleBodies.ContainsKey($bodyKey)) {
        $body = [string]$script:ArmDocumentedExampleBodies[$bodyKey]
    }

    return [pscustomobject]@{
        Name                 = $name
        Category             = [string](Get-SafeProperty -InputObject $Operation -Name 'Category')
        Description          = [string](Get-SafeProperty -InputObject $Operation -Name 'Description')
        Method               = $method
        RelativePathTemplate = $Template
        DefaultApiVersion    = [string](Get-SafeProperty -InputObject $Operation -Name 'ApiVersion')
        KnownApiVersions     = @(Get-SafeProperty -InputObject $Operation -Name 'ApiVersions')
        RequiredParameters   = $required
        OptionalParameters   = @()
        Notes                = @(Get-SafeProperty -InputObject $Operation -Name 'Notes')
        ProviderNamespace    = [string](Get-SafeProperty -InputObject $Operation -Name 'ProviderNamespace')
        ResourceType         = [string](Get-SafeProperty -InputObject $Operation -Name 'ResourceType')
        RouteSource          = [string](Get-SafeProperty -InputObject $Operation -Name 'RouteSource')
        Source               = 'Extended'
        IsPreset             = $false
        IsDiscoveredProjection = $true
        HasDefaultBody       = (-not [string]::IsNullOrEmpty($body))
        ExampleBody          = $body
        ExampleParameters    = $examples
    }
}

function Set-WelcomeVisible {
    param([Parameter(Mandatory = $true)][bool]$Visible)
    $ui.PanelWelcome.Visibility = if ($Visible) { 'Visible' } else { 'Collapsed' }
    if ($Visible) { $ui.ScrollRequest.ScrollToTop() }
}

function Select-DiscoveredOperation {
    param([Parameter(Mandatory = $true)][object]$Operation)

    $script:App.SelectedDiscovered = $Operation
    $name = [string](Get-SafeProperty -InputObject $Operation -Name 'Name')
    $variants = @(Get-SafeProperty -InputObject $Operation -Name 'ScopeVariants')
    if ($variants.Count -eq 0) {
        Set-Status ('Discovered operation ' + $name + ' has no callable scope and cannot be built here.') -Kind 'Problem'
        return
    }
    Set-WelcomeVisible -Visible $false

    # Repopulating the picker raises SelectionChanged, which would rebuild twice.
    $script:App.ScopeSuppress = $true
    $ui.CmbScope.Items.Clear()
    foreach ($variant in $variants) {
        $ui.CmbScope.Items.Add(('{0}  ({1} confidence)' -f $variant.Scope, $variant.Confidence)) | Out-Null
    }
    $ui.CmbScope.SelectedIndex = 0
    $script:App.ScopeSuppress = $false

    $ui.PanelScope.Visibility = 'Visible'
    $ui.TxtScopeEvidence.Text = [string]$variants[0].Evidence
    $ui.BorderProvenance.Visibility = 'Visible'
    $risk = [string](Get-SafeProperty -InputObject $Operation -Name 'Risk')
    $route = [string](Get-SafeProperty -InputObject $Operation -Name 'RouteSource')
    if ($route -ne 'Documented') { $route = 'INFERRED PATH' } else { $route = 'DOCUMENTED PATH' }
    $ui.TxtProvenance.Text = ('DISCOVERED  {0}  {1}' -f $risk.ToUpperInvariant(), $route)

    # Preset mode, not Path mode: Path mode collapses PanelPreset, which is the parent
    # of the scope picker and the parameter list, and sends placeholders unresolved.
    $ui.RbPreset.IsChecked = $true
    Build-DiscoveredParameterPane -Template ([string]$variants[0].Template) -Keep $false
    Set-Status ('Discovered operation ' + $name + '. Verify the scope, then fill in the values.')
}

# Rebuilds the projection and its parameter rows for one scope variant, carrying over
# any values the user already typed for placeholders the new template still has.
function Build-DiscoveredParameterPane {
    param([Parameter(Mandatory = $true)][string]$Template, [bool]$Keep = $true)

    $operation = $script:App.SelectedDiscovered
    if ($null -eq $operation) { return }

    $stash = @{}
    $keptApiVersion = ''
    if ($Keep) {
        foreach ($key in @($script:App.ParamBoxes.Keys)) {
            $value = Get-ParamBoxValue -Control $script:App.ParamBoxes[$key]
            if (-not [string]::IsNullOrWhiteSpace($value)) { $stash[$key] = $value }
        }
        # The api-version belongs to the resource type, not to the scope.
        $keptApiVersion = [string]$ui.CmbApiVersion.Text
    }

    $projection = New-DiscoveredProjection -Operation $operation -Template $Template
    $script:App.SelectedPreset = $projection
    $script:App.ParamBoxes = @{}
    Update-DocsLink -Operation $operation

    $ui.TxtPresetName.Text = $projection.Name
    $ui.TxtPresetDesc.Text = $projection.Description
    $ui.TxtPresetPath.Text = $Template
    $ui.PnlPresetParams.Items.Clear()

    $notes = @($projection.Notes)
    if ($notes.Count -gt 0) {
        $ui.TxtPresetNotes.Text = ($notes -join '  ')
        $ui.TxtPresetNotes.Visibility = 'Visible'
    }
    else { $ui.TxtPresetNotes.Visibility = 'Collapsed' }

    foreach ($placeholder in @($projection.RequiredParameters)) {
        $seed = ''
        if ($stash.ContainsKey($placeholder)) { $seed = [string]$stash[$placeholder] }
        Add-ParameterRow -Name $placeholder -Preset $projection -IsRequired $true -InitialValue $seed
    }

    $ui.CmbMethod.SelectedItem = $projection.Method
    $ui.CmbApiVersion.Items.Clear()
    foreach ($version in @($projection.KnownApiVersions)) { $ui.CmbApiVersion.Items.Add($version) | Out-Null }
    $ui.CmbApiVersion.Text = if ($keptApiVersion) { $keptApiVersion } else { $projection.DefaultApiVersion }

    if ($projection.HasDefaultBody) {
        $ui.TxtBodyHint.Text = 'A documented example body is available for this operation. Select Use example to load it, then edit it before sending.'
    }
    elseif ($projection.Method -in @('POST', 'PUT', 'PATCH')) {
        $ui.TxtBodyHint.Text = 'No request-body schema is published for a discovered operation. Use the documentation link beside the name to check what this call expects.'
    }
    else { $ui.TxtBodyHint.Text = '' }

    Update-EffectiveRequest
}

function Select-DiscoveredScopeVariant {
    if ($script:App.ScopeSuppress) { return }
    $operation = $script:App.SelectedDiscovered
    if ($null -eq $operation) { return }
    $variants = @(Get-SafeProperty -InputObject $operation -Name 'ScopeVariants')
    $index = $ui.CmbScope.SelectedIndex
    if ($index -lt 0 -or $index -ge $variants.Count) { return }
    $ui.TxtScopeEvidence.Text = [string]$variants[$index].Evidence
    Build-DiscoveredParameterPane -Template ([string]$variants[$index].Template) -Keep $true
}

function Get-PresetPlaceholders {
    param([Parameter(Mandatory = $true)][string]$Template)
    $found = [regex]::Matches($Template, '\{([A-Za-z0-9]+)\}')
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($m in $found) {
        $value = $m.Groups[1].Value
        if (-not $names.Contains($value)) { $names.Add($value) }
    }
    return $names
}

# Curated presets that live here rather than in the core catalog. The core's
# Get-ArmOperationPreset only resolves its own hardcoded names, so these dispatch
# by relative path instead of by -Operation.
function Get-ArmGuiExtendedPresetCatalog {
    $rows = @(
        @{ N = 'ComputeVmListBySubscription'; C = 'Compute'; M = 'GET'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines'; D = 'List every virtual machine in the subscription.' }
        @{ N = 'ComputeVmList'; C = 'Compute'; M = 'GET'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines'; D = 'List virtual machines in a resource group.' }
        @{ N = 'ComputeVmGet'; C = 'Compute'; M = 'GET'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}'; D = 'Get a virtual machine.' }
        @{ N = 'ComputeVmInstanceView'; C = 'Compute'; M = 'GET'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/instanceView'; D = 'Get the runtime status of a virtual machine.' }
        @{ N = 'ComputeVmStart'; C = 'Compute'; M = 'POST'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/start'; D = 'Start a virtual machine.' }
        @{ N = 'ComputeVmRestart'; C = 'Compute'; M = 'POST'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/restart'; D = 'Restart a virtual machine.' }
        @{ N = 'ComputeVmPowerOff'; C = 'Compute'; M = 'POST'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/powerOff'; D = 'Stop a virtual machine without releasing its compute reservation.' }
        @{ N = 'ComputeVmDeallocate'; C = 'Compute'; M = 'POST'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/deallocate'; D = 'Stop and deallocate a virtual machine so billing stops.' }
        @{ N = 'ComputeVmDelete'; C = 'Compute'; M = 'DELETE'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}'; D = 'Delete a virtual machine.' }
        @{ N = 'ComputeVmRunCommandList'; C = 'Compute'; M = 'GET'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/runCommands'; D = 'List run commands applied to a virtual machine.' }
        @{ N = 'ComputeVmExtensionList'; C = 'Compute'; M = 'GET'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/extensions'; D = 'List extensions installed on a virtual machine.' }
        @{ N = 'ComputeDiskList'; C = 'Compute'; M = 'GET'; V = '2023-10-02'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/disks'; D = 'List managed disks in the subscription.' }
        @{ N = 'ComputeSnapshotList'; C = 'Compute'; M = 'GET'; V = '2023-10-02'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/snapshots'; D = 'List disk snapshots in the subscription.' }
        @{ N = 'ComputeVmssList'; C = 'Compute'; M = 'GET'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets'; D = 'List virtual machine scale sets in the subscription.' }
        @{ N = 'ComputeVmssInstanceList'; C = 'Compute'; M = 'GET'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{scaleSetName}/virtualMachines'; D = 'List instances in a scale set.' }
        @{ N = 'ComputeUsageByLocation'; C = 'Compute'; M = 'GET'; V = '2024-07-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/usages'; D = 'Show compute quota usage for a region.' }

        @{ N = 'StorageAccountListBySubscription'; C = 'Storage'; M = 'GET'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts'; D = 'List every storage account in the subscription.' }
        @{ N = 'StorageAccountList'; C = 'Storage'; M = 'GET'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts'; D = 'List storage accounts in a resource group.' }
        @{ N = 'StorageAccountGet'; C = 'Storage'; M = 'GET'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{storageAccountName}'; D = 'Get a storage account.' }
        @{ N = 'StorageAccountListKeys'; C = 'Storage'; M = 'POST'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{storageAccountName}/listKeys'; D = 'List the access keys for a storage account.'; T = 'Returns live credentials. The response is redacted until you reveal it.' }
        @{ N = 'StorageAccountRegenerateKey'; C = 'Storage'; M = 'POST'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{storageAccountName}/regenerateKey'; D = 'Regenerate a storage account access key.'; B = '{"keyName":"key1"}'; T = 'Rotating a key breaks every client still using it.' }
        @{ N = 'StorageContainerList'; C = 'Storage'; M = 'GET'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{storageAccountName}/blobServices/default/containers'; D = 'List blob containers in a storage account.' }
        @{ N = 'StorageFileShareList'; C = 'Storage'; M = 'GET'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{storageAccountName}/fileServices/default/shares'; D = 'List file shares in a storage account.' }

        @{ N = 'NetworkVNetListBySubscription'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks'; D = 'List virtual networks in the subscription.' }
        @{ N = 'NetworkVNetList'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks'; D = 'List virtual networks in a resource group.' }
        @{ N = 'NetworkVNetGet'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{virtualNetworkName}'; D = 'Get a virtual network.' }
        @{ N = 'NetworkSubnetList'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{virtualNetworkName}/subnets'; D = 'List subnets in a virtual network.' }
        @{ N = 'NetworkSecurityGroupList'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkSecurityGroups'; D = 'List network security groups in a resource group.' }
        @{ N = 'NetworkSecurityGroupGet'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkSecurityGroups/{networkSecurityGroupName}'; D = 'Get a network security group and its rules.' }
        @{ N = 'NetworkPublicIpList'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Network/publicIPAddresses'; D = 'List public IP addresses in the subscription.' }
        @{ N = 'NetworkInterfaceList'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces'; D = 'List network interfaces in the subscription.' }
        @{ N = 'NetworkLoadBalancerList'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Network/loadBalancers'; D = 'List load balancers in the subscription.' }
        @{ N = 'NetworkPrivateEndpointList'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Network/privateEndpoints'; D = 'List private endpoints in the subscription.' }
        @{ N = 'NetworkRouteTableList'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Network/routeTables'; D = 'List route tables in the subscription.' }
        @{ N = 'NetworkPrivateDnsZoneList'; C = 'Network'; M = 'GET'; V = '2020-06-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Network/privateDnsZones'; D = 'List private DNS zones in the subscription.' }
        @{ N = 'NetworkDnsZoneList'; C = 'Network'; M = 'GET'; V = '2018-05-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Network/dnszones'; D = 'List public DNS zones in the subscription.' }
        @{ N = 'NetworkApplicationGatewayList'; C = 'Network'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGateways'; D = 'List application gateways in the subscription.' }

        @{ N = 'WebAppListBySubscription'; C = 'Web'; M = 'GET'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Web/sites'; D = 'List every app service and function app in the subscription.' }
        @{ N = 'WebAppList'; C = 'Web'; M = 'GET'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites'; D = 'List web apps in a resource group.' }
        @{ N = 'WebAppGet'; C = 'Web'; M = 'GET'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}'; D = 'Get a web app.' }
        @{ N = 'WebAppConfigGet'; C = 'Web'; M = 'GET'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/config/web'; D = 'Get the site configuration for a web app.' }
        @{ N = 'WebAppRestart'; C = 'Web'; M = 'POST'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/restart'; D = 'Restart a web app.' }
        @{ N = 'WebAppStop'; C = 'Web'; M = 'POST'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/stop'; D = 'Stop a web app.' }
        @{ N = 'WebAppStart'; C = 'Web'; M = 'POST'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/start'; D = 'Start a web app.' }
        @{ N = 'WebAppSlotList'; C = 'Web'; M = 'GET'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/slots'; D = 'List deployment slots for a web app.' }
        @{ N = 'WebAppFunctionList'; C = 'Web'; M = 'GET'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/functions'; D = 'List functions in a function app.' }
        @{ N = 'AppServicePlanList'; C = 'Web'; M = 'GET'; V = '2023-12-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Web/serverfarms'; D = 'List app service plans in the subscription.' }

        @{ N = 'AksClusterListBySubscription'; C = 'Containers'; M = 'GET'; V = '2024-05-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters'; D = 'List AKS clusters in the subscription.' }
        @{ N = 'AksClusterGet'; C = 'Containers'; M = 'GET'; V = '2024-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerService/managedClusters/{clusterName}'; D = 'Get an AKS cluster.' }
        @{ N = 'AksNodePoolList'; C = 'Containers'; M = 'GET'; V = '2024-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerService/managedClusters/{clusterName}/agentPools'; D = 'List node pools in an AKS cluster.' }
        @{ N = 'AksClusterListUserCredential'; C = 'Containers'; M = 'POST'; V = '2024-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerService/managedClusters/{clusterName}/listClusterUserCredential'; D = 'Get the user kubeconfig for an AKS cluster.'; T = 'Returns live credentials. The response is redacted until you reveal it.' }
        @{ N = 'AcrRegistryList'; C = 'Containers'; M = 'GET'; V = '2023-07-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.ContainerRegistry/registries'; D = 'List container registries in the subscription.' }
        @{ N = 'AcrRegistryGet'; C = 'Containers'; M = 'GET'; V = '2023-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}'; D = 'Get a container registry.' }
        @{ N = 'ContainerAppList'; C = 'Containers'; M = 'GET'; V = '2024-03-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.App/containerApps'; D = 'List container apps in the subscription.' }
        @{ N = 'ContainerInstanceList'; C = 'Containers'; M = 'GET'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.ContainerInstance/containerGroups'; D = 'List container instance groups in the subscription.' }

        @{ N = 'SqlServerList'; C = 'Databases'; M = 'GET'; V = '2021-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Sql/servers'; D = 'List SQL servers in the subscription.' }
        @{ N = 'SqlDatabaseList'; C = 'Databases'; M = 'GET'; V = '2021-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases'; D = 'List databases on a SQL server.' }
        @{ N = 'SqlDatabaseGet'; C = 'Databases'; M = 'GET'; V = '2021-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}'; D = 'Get a SQL database.' }
        @{ N = 'SqlFirewallRuleList'; C = 'Databases'; M = 'GET'; V = '2021-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/firewallRules'; D = 'List firewall rules on a SQL server.' }
        @{ N = 'CosmosAccountList'; C = 'Databases'; M = 'GET'; V = '2024-05-15'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts'; D = 'List Cosmos DB accounts in the subscription.' }
        @{ N = 'CosmosAccountListKeys'; C = 'Databases'; M = 'POST'; V = '2024-05-15'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DocumentDB/databaseAccounts/{accountName}/listKeys'; D = 'List the access keys for a Cosmos DB account.'; T = 'Returns live credentials. The response is redacted until you reveal it.' }
        @{ N = 'PostgreSqlFlexibleServerList'; C = 'Databases'; M = 'GET'; V = '2022-12-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/flexibleServers'; D = 'List PostgreSQL flexible servers in the subscription.' }
        @{ N = 'MySqlFlexibleServerList'; C = 'Databases'; M = 'GET'; V = '2023-06-30'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/flexibleServers'; D = 'List MySQL flexible servers in the subscription.' }
        @{ N = 'RedisCacheList'; C = 'Databases'; M = 'GET'; V = '2024-03-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Cache/redis'; D = 'List Redis caches in the subscription.' }
        @{ N = 'RedisCacheListKeys'; C = 'Databases'; M = 'POST'; V = '2024-03-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cache/redis/{cacheName}/listKeys'; D = 'List the access keys for a Redis cache.'; T = 'Returns live credentials. The response is redacted until you reveal it.' }

        @{ N = 'RoleAssignmentList'; C = 'Identity'; M = 'GET'; V = '2022-04-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments'; D = 'List role assignments at subscription scope.' }
        @{ N = 'RoleAssignmentListByResourceGroup'; C = 'Identity'; M = 'GET'; V = '2022-04-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/roleAssignments'; D = 'List role assignments at resource-group scope.' }
        @{ N = 'RoleDefinitionList'; C = 'Identity'; M = 'GET'; V = '2022-04-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions'; D = 'List role definitions available at subscription scope.' }
        @{ N = 'ManagedIdentityList'; C = 'Identity'; M = 'GET'; V = '2023-01-31'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.ManagedIdentity/userAssignedIdentities'; D = 'List user-assigned managed identities in the subscription.' }
        @{ N = 'DenyAssignmentList'; C = 'Identity'; M = 'GET'; V = '2022-04-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/denyAssignments'; D = 'List deny assignments at subscription scope.' }

        @{ N = 'LogAnalyticsWorkspaceList'; C = 'Monitor'; M = 'GET'; V = '2022-10-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.OperationalInsights/workspaces'; D = 'List Log Analytics workspaces in the subscription.' }
        @{ N = 'LogAnalyticsWorkspaceGet'; C = 'Monitor'; M = 'GET'; V = '2022-10-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}'; D = 'Get a Log Analytics workspace.' }
        @{ N = 'MetricAlertList'; C = 'Monitor'; M = 'GET'; V = '2018-03-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Insights/metricAlerts'; D = 'List metric alert rules in the subscription.' }
        @{ N = 'ActionGroupList'; C = 'Monitor'; M = 'GET'; V = '2023-01-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Insights/actionGroups'; D = 'List action groups in the subscription.' }
        @{ N = 'AutoscaleSettingList'; C = 'Monitor'; M = 'GET'; V = '2022-10-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Insights/autoscalesettings'; D = 'List autoscale settings in the subscription.' }
        @{ N = 'ActivityLogList'; C = 'Monitor'; M = 'GET'; V = '2015-04-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Insights/eventtypes/management/values'; D = 'Read the activity log. Add a $filter query for a time range.'; T = 'Activity log queries usually need a $filter such as eventTimestamp ge to avoid a very large response.' }
        @{ N = 'ScheduledQueryRuleList'; C = 'Monitor'; M = 'GET'; V = '2023-03-15-preview'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Insights/scheduledQueryRules'; D = 'List log alert rules in the subscription.' }
        @{ N = 'ApplicationInsightsList'; C = 'Monitor'; M = 'GET'; V = '2020-02-02'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Insights/components'; D = 'List Application Insights components in the subscription.' }

        @{ N = 'KeyVaultListBySubscription'; C = 'KeyVault'; M = 'GET'; V = '2023-07-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults'; D = 'List key vaults in the subscription.' }
        @{ N = 'KeyVaultList'; C = 'KeyVault'; M = 'GET'; V = '2023-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults'; D = 'List key vaults in a resource group.' }
        @{ N = 'KeyVaultGet'; C = 'KeyVault'; M = 'GET'; V = '2023-07-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}'; D = 'Get a key vault, including its access model.' }
        @{ N = 'KeyVaultDeletedList'; C = 'KeyVault'; M = 'GET'; V = '2023-07-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/deletedVaults'; D = 'List soft-deleted key vaults awaiting purge or recovery.' }

        @{ N = 'ServiceBusNamespaceList'; C = 'Messaging'; M = 'GET'; V = '2021-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.ServiceBus/namespaces'; D = 'List Service Bus namespaces in the subscription.' }
        @{ N = 'ServiceBusQueueList'; C = 'Messaging'; M = 'GET'; V = '2021-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/queues'; D = 'List queues in a Service Bus namespace.' }
        @{ N = 'ServiceBusTopicList'; C = 'Messaging'; M = 'GET'; V = '2021-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/topics'; D = 'List topics in a Service Bus namespace.' }
        @{ N = 'EventHubNamespaceList'; C = 'Messaging'; M = 'GET'; V = '2021-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.EventHub/namespaces'; D = 'List Event Hubs namespaces in the subscription.' }
        @{ N = 'EventHubList'; C = 'Messaging'; M = 'GET'; V = '2021-11-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.EventHub/namespaces/{namespaceName}/eventhubs'; D = 'List event hubs in a namespace.' }
        @{ N = 'EventGridTopicList'; C = 'Messaging'; M = 'GET'; V = '2022-06-15'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.EventGrid/topics'; D = 'List Event Grid topics in the subscription.' }

        @{ N = 'SubscriptionList'; C = 'Governance'; M = 'GET'; V = '2022-12-01'; P = '/subscriptions'; D = 'List every subscription the signed-in account can see.' }
        @{ N = 'TenantList'; C = 'Governance'; M = 'GET'; V = '2022-12-01'; P = '/tenants'; D = 'List every tenant the signed-in account can see.' }
        @{ N = 'LocationList'; C = 'Governance'; M = 'GET'; V = '2022-12-01'; P = '/subscriptions/{subscriptionId}/locations'; D = 'List regions available to the subscription.' }
        @{ N = 'ResourceListBySubscription'; C = 'Governance'; M = 'GET'; V = '2021-04-01'; P = '/subscriptions/{subscriptionId}/resources'; D = 'List every resource in the subscription.' }
        @{ N = 'ManagementGroupList'; C = 'Governance'; M = 'GET'; V = '2021-04-01'; P = '/providers/Microsoft.Management/managementGroups'; D = 'List management groups in the tenant.' }
        @{ N = 'PolicyDefinitionList'; C = 'Governance'; M = 'GET'; V = '2023-04-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyDefinitions'; D = 'List policy definitions at subscription scope.' }
        @{ N = 'PolicySetDefinitionList'; C = 'Governance'; M = 'GET'; V = '2023-04-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policySetDefinitions'; D = 'List policy initiatives at subscription scope.' }
        @{ N = 'PolicyStateSummarize'; C = 'Governance'; M = 'POST'; V = '2019-10-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize'; D = 'Summarize policy compliance for the subscription.' }
        @{ N = 'ResourceTagNameList'; C = 'Governance'; M = 'GET'; V = '2021-04-01'; P = '/subscriptions/{subscriptionId}/tagNames'; D = 'List tag names and values used in the subscription.' }
        @{ N = 'ResourceGroupExportTemplate'; C = 'Governance'; M = 'POST'; V = '2021-04-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/exportTemplate'; D = 'Export a resource group as an ARM template.'; B = '{"resources":["*"],"options":"SkipResourceNameParameterization"}' }
        @{ N = 'DeploymentOperationList'; C = 'Governance'; M = 'GET'; V = '2021-04-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}/operations'; D = 'List the individual operations of a deployment. Useful for finding the failing resource.' }
        @{ N = 'ProviderRegister'; C = 'Governance'; M = 'POST'; V = '2021-04-01'; P = '/subscriptions/{subscriptionId}/providers/{providerNamespace}/register'; D = 'Register a resource provider on the subscription.' }
        @{ N = 'ProviderUnregister'; C = 'Governance'; M = 'POST'; V = '2021-04-01'; P = '/subscriptions/{subscriptionId}/providers/{providerNamespace}/unregister'; D = 'Unregister a resource provider from the subscription.' }

        @{ N = 'AdvisorRecommendationList'; C = 'Operations'; M = 'GET'; V = '2020-01-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Advisor/recommendations'; D = 'List Azure Advisor recommendations for the subscription.' }
        @{ N = 'ResourceHealthList'; C = 'Operations'; M = 'GET'; V = '2022-10-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.ResourceHealth/availabilityStatuses'; D = 'List the current health of every resource in the subscription.' }
        @{ N = 'SupportTicketList'; C = 'Operations'; M = 'GET'; V = '2020-04-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Support/supportTickets'; D = 'List support tickets raised on the subscription.' }
        @{ N = 'RecoveryVaultList'; C = 'Operations'; M = 'GET'; V = '2024-04-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.RecoveryServices/vaults'; D = 'List Recovery Services vaults in the subscription.' }
        @{ N = 'BackupProtectedItemList'; C = 'Operations'; M = 'GET'; V = '2024-04-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupProtectedItems'; D = 'List protected items in a Recovery Services vault.' }
        @{ N = 'CognitiveAccountList'; C = 'Operations'; M = 'GET'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.CognitiveServices/accounts'; D = 'List Azure AI service accounts in the subscription.' }
        @{ N = 'CognitiveAccountListKeys'; C = 'Operations'; M = 'POST'; V = '2023-05-01'; P = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}/listKeys'; D = 'List the access keys for an Azure AI service account.'; T = 'Returns live credentials. The response is redacted until you reveal it.' }
        @{ N = 'SearchServiceList'; C = 'Operations'; M = 'GET'; V = '2023-11-01'; P = '/subscriptions/{subscriptionId}/providers/Microsoft.Search/searchServices'; D = 'List Azure AI Search services in the subscription.' }
    )

    foreach ($row in $rows) {
        $placeholders = @([regex]::Matches($row.P, '\{([A-Za-z0-9]+)\}') | ForEach-Object { $_.Groups[1].Value })
        $namespace = ''
        if ($row.P -match '/providers/([A-Za-z0-9\.]+)/') { $namespace = $Matches[1] }
        $body = ''
        if ($row.ContainsKey('B')) { $body = [string]$row.B }
        $notes = @()
        if ($row.ContainsKey('T')) { $notes = @([string]$row.T) }

        [pscustomobject]@{
            Name = $row.N; Category = $row.C; Description = $row.D
            Method = $row.M; RelativePathTemplate = $row.P
            DefaultApiVersion = $row.V; Aliases = @()
            RequiredParameters = $placeholders; OptionalParameters = @()
            KnownApiVersions = @($row.V); Notes = $notes
            ProviderNamespace = $namespace; ResourceType = ''
            IsPreset = $true
            Source = 'Extended'
            SearchBlob = (@(@($row.N, $row.C, $row.D, $row.M, $row.P, $namespace) |
                        Where-Object { -not [string]::IsNullOrEmpty($_) }) -join ' ').ToUpperInvariant()
            HasDefaultBody = (-not [string]::IsNullOrEmpty($body))
            ExampleBody = $body
            ExampleParameters = @{}
        }
    }
}

# Parameter defaults are stored encrypted with DPAPI scoped to the current user, so a
# copied file is useless elsewhere and the values cannot be found by a plain-text scan.
$script:DefaultsEntropy = [byte[]](0x41, 0x72, 0x6D, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x50, 0x53, 0x44, 0x65, 0x66, 0x01)

function Get-DefaultsDirectory {
    Join-Path $env:LOCALAPPDATA 'ArmClient-PS'
}

function Get-DefaultsPath {
    Join-Path (Get-DefaultsDirectory) 'parameter-defaults.dat'
}

function ConvertFrom-DefaultsText {
    param([AllowNull()][string]$Text)
    $table = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return $table }
    foreach ($line in ($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }
        $index = $trimmed.IndexOf('=')
        if ($index -lt 1) { throw "Line '$trimmed' is not in 'name = value' format." }
        $name = $trimmed.Substring(0, $index).Trim()
        $value = $trimmed.Substring($index + 1).Trim()
        if ($name -notmatch '^[A-Za-z0-9]+$') { throw "Parameter name '$name' must be letters and digits only." }
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        $table[$name] = $value
    }
    return $table
}

function ConvertTo-DefaultsText {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Table)
    $lines = foreach ($key in $Table.Keys) { '{0} = {1}' -f $key, $Table[$key] }
    ($lines -join [Environment]::NewLine)
}

function Set-UserOnlyAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { $null = $acl.RemoveAccessRule($rule) }
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')))
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    catch { }   # inherited permissions still apply; encryption is the real control
}

function Save-ParameterDefaults {
    param([Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Table,
        [switch]$Plain)

    $json = ($Table | ConvertTo-Json -Depth 5)
    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) { $null = New-Item -Path $directory -ItemType Directory -Force }

    if ($Plain) {
        $writer = [IO.StreamWriter]::new($Path, $false, [Text.UTF8Encoding]::new($false))
        try { $writer.Write($json) } finally { $writer.Dispose() }
    }
    else {
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        try {
            $protected = [System.Security.Cryptography.ProtectedData]::Protect(
                $bytes, $script:DefaultsEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        }
        finally { [Array]::Clear($bytes, 0, $bytes.Length) }
        [IO.File]::WriteAllBytes($Path, $protected)
    }
    Set-UserOnlyAcl -Path $Path
    return $Path
}

function Import-ParameterDefaults {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $raw = [IO.File]::ReadAllBytes($Path)
    $json = $null
    try {
        $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $raw, $script:DefaultsEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $json = [Text.Encoding]::UTF8.GetString($plainBytes)
        [Array]::Clear($plainBytes, 0, $plainBytes.Length)
    }
    catch {
        # Not a blob this user can decrypt, so fall back to a plain export.
        $json = [Text.Encoding]::UTF8.GetString($raw)
        if ($json -notmatch '^\s*\{') {
            throw 'This defaults file was encrypted for a different user or machine and cannot be read here.'
        }
    }
    $parsed = $json | ConvertFrom-Json -ErrorAction Stop
    $table = [ordered]@{}
    foreach ($property in $parsed.PSObject.Properties) {
        if ($property.Name -match '^[A-Za-z0-9]+$') { $table[$property.Name] = [string]$property.Value }
    }
    return $table
}

function Set-ParameterDefaults {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Table)
    $script:App.Defaults = $Table
    $ui.TxtDefaults.Text = ConvertTo-DefaultsText -Table $Table
}

function Use-ParameterDefaults {
    $applied = 0
    foreach ($key in @($script:App.ParamBoxes.Keys)) {
        if (-not $script:App.Defaults.Contains($key)) { continue }
        $control = $script:App.ParamBoxes[$key]
        if ($control -is [System.Windows.Controls.ComboBox] -and -not $control.IsEditable) { continue }
        $control.Text = [string]$script:App.Defaults[$key]
        $applied++
    }
    Update-EffectiveRequest
    return $applied
}

# Validation verdicts for saved defaults, keyed by parameter name.
# Valid   = confirmed present in the current tenant
# Invalid = confirmed absent, and the only state that blocks closing the dialog
# Unknown = not checkable, not yet checked, blocked by a bad parent, or the check failed
$script:DefaultsState = @{}

function Set-DefaultsStateAll {
    param([string]$State = 'Unknown', [string]$Detail = '')
    # Mutated, never reassigned, so handlers can capture the reference as a local.
    $script:DefaultsState.Clear()
    foreach ($key in @($script:App.Defaults.Keys)) {
        if (-not $key) { continue }
        $script:DefaultsState[$key] = @{ State = $State; Detail = $Detail }
    }
}

function Get-DefaultsStateFor {
    param([string]$Name)
    if ($script:DefaultsState.ContainsKey($Name)) { return $script:DefaultsState[$Name] }
    return @{ State = 'Unknown'; Detail = '' }
}

function Test-DefaultsHaveInvalid {
    foreach ($key in @($script:DefaultsState.Keys)) {
        if (-not $script:App.Defaults.Contains($key)) { continue }
        if ([string]$script:DefaultsState[$key].State -eq 'Invalid') { return $true }
    }
    return $false
}

# Builds the check list on the UI thread. Values come from the saved defaults only,
# never from the parameter boxes, which may still hold the previous tenant's values.
function Get-DefaultsValidationPlan {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Values,
        [AllowNull()][object]$Preset)

    $plan = New-Object System.Collections.Generic.List[object]
    $state = @{}
    $template = ''
    if ($null -ne $Preset) { $template = [string]$Preset.RelativePathTemplate }

    # Shallowest placeholder first, so a parent is decided before its children.
    $ordered = @($Values.Keys | Where-Object { $_ } | Sort-Object {
            if ($_ -eq 'subscriptionId') { return -1 }
            if (-not $template) { return 10000 }
            $at = $template.IndexOf(('{' + $_ + '}'), [System.StringComparison]::OrdinalIgnoreCase)
            if ($at -lt 0) { return 10000 }
            return $at
        }, { $_ })

    foreach ($name in $ordered) {
        $value = ([string]$Values[$name]).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) {
            $state[$name] = @{ State = 'Invalid'; Detail = 'The value is empty.' }
            continue
        }
        if ($name -eq 'subscriptionId') {
            $plan.Add([pscustomobject]@{ Name = $name; Value = $value; Kind = 'Subscription'; Path = ''; ApiVersion = '' }) | Out-Null
            $state[$name] = @{ State = 'Unknown'; Detail = 'Checking the subscription list.' }
            continue
        }
        if (-not $template) {
            $state[$name] = @{ State = 'Unknown'; Detail = 'Select an operation that uses this name to check it.' }
            continue
        }

        $at = $template.IndexOf(('{' + $name + '}'), [System.StringComparison]::OrdinalIgnoreCase)
        if ($at -lt 1) {
            $state[$name] = @{ State = 'Unknown'; Detail = 'This name has no collection endpoint to check against.' }
            continue
        }
        $prefix = $template.Substring(0, $at).TrimEnd('/')
        $blocked = ''
        foreach ($match in [regex]::Matches($prefix, '\{([A-Za-z0-9]+)\}')) {
            $dependency = $match.Groups[1].Value
            if (-not $Values.Contains($dependency) -or [string]::IsNullOrWhiteSpace([string]$Values[$dependency])) {
                $blocked = $dependency; break
            }
            # Only a confirmed failure blocks a child. A parent still awaiting its own
            # check must not stop the child from being checked, or nothing below the
            # first level would ever be verified.
            if ($state.ContainsKey($dependency) -and [string]$state[$dependency].State -eq 'Invalid') {
                $blocked = $dependency; break
            }
            $prefix = $prefix.Replace($match.Value, [System.Uri]::EscapeDataString(([string]$Values[$dependency]).Trim()))
        }
        if ($blocked) {
            $state[$name] = @{ State = 'Unknown'; Detail = ('Cannot check until {0} is resolved.' -f $blocked) }
            continue
        }

        $apiVersion = [string]$Preset.DefaultApiVersion
        if ([string]::IsNullOrWhiteSpace($apiVersion)) { $apiVersion = '2021-04-01' }
        $plan.Add([pscustomobject]@{ Name = $name; Value = $value; Kind = 'Collection'; Path = $prefix; ApiVersion = $apiVersion }) | Out-Null
        $state[$name] = @{ State = 'Unknown'; Detail = 'Checking Azure.' }
    }

    # ToArray, not @(): casting a hashtable holding a generic List to pscustomobject
    # throws "Argument types do not match" on both 5.1 and 7.x.
    return [pscustomobject]@{ Plan = $plan.ToArray(); State = $state }
}

# Runs in the worker runspace. One subscription call plus one list call per distinct
# parent collection, rather than one call per default.
function global:Test-ArmGuiDefaultPlan {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $results = New-Object System.Collections.Generic.List[object]
    $items = @($Plan)

    $subscriptionItems = @($items | Where-Object { $_.Kind -eq 'Subscription' })
    if ($subscriptionItems.Count -gt 0) {
        $known = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($subscription in (Get-AzSubscription -ErrorAction Stop)) {
            if ($subscription.Id) { $null = $known.Add([string]$subscription.Id) }
        }
        foreach ($item in $subscriptionItems) {
            if ($known.Contains([string]$item.Value)) {
                $results.Add([pscustomobject]@{ Name = $item.Name; State = 'Valid'; Detail = '' }) | Out-Null
            }
            else {
                $results.Add([pscustomobject]@{ Name = $item.Name; State = 'Invalid'
                        Detail = 'This subscription is not in the current tenant.'
                    }) | Out-Null
            }
        }
    }

    $groups = @($items | Where-Object { $_.Kind -eq 'Collection' } | Group-Object -Property Path)
    foreach ($group in $groups) {
        $sample = @($group.Group)[0]
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $failed = ''
        try {
            foreach ($name in @(Get-ArmGuiResourceNames -Path $sample.Path -ApiVersion $sample.ApiVersion)) {
                if ($name) { $null = $names.Add([string]$name) }
            }
        }
        catch { $failed = $_.Exception.Message }

        foreach ($item in @($group.Group)) {
            if ($failed) {
                $results.Add([pscustomobject]@{ Name = $item.Name; State = 'Unknown'
                        Detail = 'Could not read the parent collection.'
                    }) | Out-Null
            }
            elseif ($names.Contains([string]$item.Value)) {
                $results.Add([pscustomobject]@{ Name = $item.Name; State = 'Valid'; Detail = '' }) | Out-Null
            }
            else {
                $results.Add([pscustomobject]@{ Name = $item.Name; State = 'Invalid'
                        Detail = 'Not found in this tenant.'
                    }) | Out-Null
            }
        }
    }

    foreach ($result in $results) { $result }
}

function Start-DefaultsRevalidation {
    if (@($script:App.Defaults.Keys).Count -eq 0) { return }
    Set-DefaultsStateAll -State 'Unknown' -Detail 'Not checked against this tenant yet.'
    Show-DefaultsDialog
}

# Runs one batched worker job for the whole defaults table. Lazy, on dialog open,
# because the check costs an ARM round trip per distinct parent collection.
function Start-DefaultsValidation {
    param([Parameter(Mandatory = $true)][hashtable]$Controls,
        [Parameter(Mandatory = $true)][scriptblock]$Refresh)

    if (@($script:App.Defaults.Keys).Count -eq 0) { return }
    if ($null -eq $script:App.Context) {
        Set-DefaultsStateAll -State 'Unknown' -Detail 'Sign in to check these against Azure.'
        & $Refresh
        return
    }
    if ($script:App.Busy) {
        $Controls.TxtDlgContext.Text = 'Azure is busy with another operation, so saved values were not re-checked.'
        return
    }

    $built = Get-DefaultsValidationPlan -Values $script:App.Defaults -Preset $script:App.SelectedPreset
    $previous = @{}
    foreach ($key in @($script:DefaultsState.Keys)) { $previous[$key] = $script:DefaultsState[$key] }
    $script:DefaultsState.Clear()
    foreach ($key in @($built.State.Keys)) {
        # A confirmed failure stays on screen while the re-check runs, rather than
        # flicking back to Unknown and briefly unblocking the close gate.
        if ($previous.ContainsKey($key) -and [string]$previous[$key].State -eq 'Invalid') {
            $script:DefaultsState[$key] = $previous[$key]
        }
        else { $script:DefaultsState[$key] = $built.State[$key] }
    }
    & $Refresh

    if (@($built.Plan).Count -eq 0) {
        $Controls.TxtDlgContext.Text = 'Nothing here could be checked against Azure automatically.'
        return
    }

    $controlsRef = $Controls
    $refreshRef = $Refresh
    $stateRef = $script:DefaultsState
    $appRef = $script:App
    $Controls.TxtDlgContext.Text = 'Checking saved values against this tenant...'
    Invoke-Worker -Script 'param($CheckPlan) Test-ArmGuiDefaultPlan -Plan $CheckPlan' `
        -Parameters @{ CheckPlan = @($built.Plan) } -StatusText 'Checking saved defaults' -OnSuccess {
        param($result)
        foreach ($item in @($result)) {
            if ($null -eq $item -or -not $item.Name) { continue }
            $stateRef[[string]$item.Name] = @{ State = [string]$item.State; Detail = [string]$item.Detail }
        }
        & $refreshRef
        $bad = 0
        foreach ($key in @($appRef.Defaults.Keys)) {
            if ($stateRef.ContainsKey($key) -and [string]$stateRef[$key].State -eq 'Invalid') { $bad++ }
        }
        $controlsRef.TxtDlgContext.Text = if ($bad -gt 0) {
            '{0} saved value(s) do not exist in this tenant. Update or remove them to close.' -f $bad
        }
        else { 'Saved values were checked against this tenant.' }
    }.GetNewClosure() -OnFailure {
        param($message)
        # A failed check must never be reported as invalid, or a network blip would
        # lock the user inside the dialog.
        foreach ($key in @($appRef.Defaults.Keys)) {
            if ($stateRef.ContainsKey($key) -and [string]$stateRef[$key].State -eq 'Invalid') { continue }
            $stateRef[[string]$key] = @{ State = 'Unknown'; Detail = 'The check could not be completed.' }
        }
        & $refreshRef
        $controlsRef.TxtDlgContext.Text = 'Saved values could not be checked. You can still close this window.'
    }.GetNewClosure()
}

$script:XamlTenantDialog = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Switch tenant" Height="520" Width="640" MinHeight="420" MinWidth="520"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        UseLayoutRounding="True" SnapsToDevicePixels="True"
        FontFamily="Segoe UI Variable Text, Segoe UI, Tahoma" FontSize="13"
        Background="{DynamicResource Bg.App}" Foreground="{DynamicResource Text.Primary}">
  <Grid Margin="18">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0" Margin="0,0,0,12">
      <TextBlock Text="Switch tenant" Style="{DynamicResource Text.Subtitle}"/>
      <TextBlock x:Name="TxtTenantCurrent" Style="{DynamicResource Text.Caption}" TextWrapping="Wrap" Margin="0,3,0,0"/>
    </StackPanel>

    <Border Grid.Row="1" Style="{DynamicResource Card}" Padding="0">
      <Grid>
        <ListBox x:Name="LstTenants" BorderThickness="0" Background="Transparent"
                 ScrollViewer.HorizontalScrollBarVisibility="Disabled"/>
        <TextBlock x:Name="TxtTenantEmpty" Text="No tenants were returned." IsHitTestVisible="False"
                   HorizontalAlignment="Center" VerticalAlignment="Center"
                   Foreground="{DynamicResource Text.Tertiary}" Visibility="Collapsed"/>
      </Grid>
    </Border>

    <Border Grid.Row="2" Background="{DynamicResource State.WarningBg}" CornerRadius="4" Padding="10,7" Margin="0,12,0,0">
      <TextBlock Style="{DynamicResource Text.Caption}" TextWrapping="Wrap"
                 Text="Switching signs this session in again and may prompt in a browser. Discovered operations and the current response are discarded, because they belong to the tenant you are leaving."/>
    </Border>

    <Grid Grid.Row="3" Margin="0,14,0,0">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="BtnTenantSwitch" Content="Switch" Style="{DynamicResource Btn.Primary}" MinWidth="100" IsEnabled="False"/>
        <Button x:Name="BtnTenantCancel" Content="Cancel" Style="{DynamicResource Btn.Secondary}" Margin="8,0,0,0" IsCancel="True"/>
      </StackPanel>
    </Grid>
  </Grid>
</Window>
'@

# Returns the chosen tenant GUID, or '' when the user cancels. The GUID is returned
# rather than the domain because the context reports a GUID, and the caller compares
# the two to prove the switch actually landed where it was asked to.
function Show-TenantDialog {
    param([Parameter(Mandatory = $true)][object[]]$Tenants, [string]$CurrentTenantId)

    $dialog = New-GuiWindow -Markup $script:XamlTenantDialog
    $dialog.Owner = $script:Window
    $dialog.Resources = $script:Window.Resources

    $t = @{}
    foreach ($name in 'TxtTenantCurrent', 'LstTenants', 'TxtTenantEmpty', 'BtnTenantSwitch', 'BtnTenantCancel') {
        $found = $dialog.FindName($name)
        if ($null -eq $found) { throw "The tenant dialog is missing a control named '$name'." }
        $t[$name] = $found
    }

    # GetNewClosure rebinds $script:, so everything the handlers need is a local.
    $dot = $script:MiddleDot
    $idByLabel = @{}
    $currentLabel = ''

    $t.TxtTenantCurrent.Text = if ($CurrentTenantId) { 'Currently signed in to tenant ' + $CurrentTenantId }
    else { 'No tenant is active.' }

    foreach ($tenant in $Tenants) {
        if ($null -eq $tenant -or -not $tenant.Id) { continue }
        $label = [string]$tenant.Id
        if ($tenant.Name) { $label = '{0}  {1}  {2}' -f $tenant.Name, $dot, $tenant.Id }
        if ($tenant.Domain) { $label = '{0}  {1}  {2}' -f $label, $dot, $tenant.Domain }
        if ([string]$tenant.Id -eq $CurrentTenantId) { $label = $label + '   (current)'; $currentLabel = $label }
        $idByLabel[$label] = [string]$tenant.Id
        $t.LstTenants.Items.Add($label) | Out-Null
    }
    if ($t.LstTenants.Items.Count -eq 0) { $t.TxtTenantEmpty.Visibility = 'Visible' }
    if ($currentLabel) { $t.LstTenants.SelectedItem = $currentLabel }

    $t.LstTenants.Add_SelectionChanged((Register-Handler {
                $selected = [string]$t.LstTenants.SelectedItem
                $t.BtnTenantSwitch.IsEnabled = ($selected -and ([string]$idByLabel[$selected] -ne $CurrentTenantId))
            }.GetNewClosure()))

    $dialog.Tag = ''
    $commit = {
        $selected = [string]$t.LstTenants.SelectedItem
        if ([string]::IsNullOrWhiteSpace($selected)) { return }
        if ([string]$idByLabel[$selected] -eq $CurrentTenantId) { return }
        $dialog.Tag = [string]$idByLabel[$selected]
        $dialog.Close()
    }.GetNewClosure()

    $t.BtnTenantSwitch.Add_Click((Register-Handler $commit))
    $t.BtnTenantCancel.Add_Click((Register-Handler { $dialog.Close() }.GetNewClosure()))

    $null = $dialog.ShowDialog()
    return [string]$dialog.Tag
}

$script:XamlSaveChoiceDialog = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Save parameter defaults" Width="580" SizeToContent="Height"
        ResizeMode="NoResize" WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        UseLayoutRounding="True" SnapsToDevicePixels="True"
        FontFamily="Segoe UI Variable Text, Segoe UI, Tahoma" FontSize="13"
        Background="{DynamicResource Bg.App}" Foreground="{DynamicResource Text.Primary}">
  <Grid Margin="18">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0">
      <TextBlock Text="Save parameter defaults" Style="{DynamicResource Text.Subtitle}"/>
      <TextBlock x:Name="TxtChoiceSummary" Style="{DynamicResource Text.Caption}" TextWrapping="Wrap" Margin="0,3,0,0"/>
    </StackPanel>

    <Border Grid.Row="1" Style="{DynamicResource Card}" Margin="0,14,0,0">
      <StackPanel>
        <RadioButton x:Name="RbSaveEncrypted" GroupName="SaveMode" IsChecked="True" VerticalContentAlignment="Top">
          <StackPanel Margin="4,0,0,0">
            <TextBlock Text="Keep it private on this PC" FontWeight="SemiBold"/>
            <TextBlock Style="{DynamicResource Text.Caption}" TextWrapping="Wrap" Margin="0,2,0,0"
                       Text="Encrypted with your Windows account, so only you on this machine can read it. It loads automatically the next time you start the tool."/>
            <TextBlock x:Name="TxtChoicePath" Style="{DynamicResource Text.Caption}" TextWrapping="Wrap" Margin="0,4,0,0"/>
          </StackPanel>
        </RadioButton>

        <Separator/>

        <RadioButton x:Name="RbSavePlain" GroupName="SaveMode" VerticalContentAlignment="Top">
          <StackPanel Margin="4,0,0,0">
            <TextBlock Text="Export unencrypted so you can share it" FontWeight="SemiBold"/>
            <TextBlock Style="{DynamicResource Text.Caption}" TextWrapping="Wrap" Margin="0,2,0,0"
                       Text="Plain JSON that a teammate can open on any machine. You choose where it goes, and this copy is not loaded automatically."/>
          </StackPanel>
        </RadioButton>
      </StackPanel>
    </Border>

    <Grid Grid.Row="2" Margin="0,12,0,0">
      <Border x:Name="BorderChoiceSafe" Background="{DynamicResource State.WarningBg}" CornerRadius="4" Padding="10,7">
        <TextBlock Style="{DynamicResource Text.Caption}" TextWrapping="Wrap"
                   Text="These values typically include subscription IDs, resource group names, and other non-public identifiers. Encryption protects the file at rest, not what you do with it afterwards."/>
      </Border>
      <Border x:Name="BorderChoiceRisk" Background="{DynamicResource State.DangerBg}" CornerRadius="4" Padding="10,7"
              Visibility="Collapsed">
        <TextBlock Style="{DynamicResource Text.Caption}" TextWrapping="Wrap"
                   Text="This copy is NOT encrypted. Anyone who can read the file, including backup, sync, and search indexing, can read every value in it. Share it only over a channel your organization approves, and never commit it to source control."/>
      </Border>
    </Grid>

    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
      <Button x:Name="BtnChoiceOk" Content="Save" Style="{DynamicResource Btn.Primary}" MinWidth="150" IsDefault="True"/>
      <Button x:Name="BtnChoiceCancel" Content="Cancel" Style="{DynamicResource Btn.Secondary}" Margin="8,0,0,0" IsCancel="True"/>
    </StackPanel>
  </Grid>
</Window>
'@

# Returns 'Encrypted', 'Plain', or '' when the user cancels.
function Show-SaveChoiceDialog {
    param([Parameter(Mandatory = $true)][int]$Count,
        [Parameter(Mandatory = $true)][string]$EncryptedPath,
        [object]$Owner)

    $choiceDialog = New-GuiWindow -Markup $script:XamlSaveChoiceDialog
    $choiceDialog.Owner = if ($null -eq $Owner) { $script:Window } else { $Owner }
    $choiceDialog.Resources = $script:Window.Resources

    $c = @{}
    foreach ($name in 'TxtChoiceSummary', 'TxtChoicePath', 'RbSaveEncrypted', 'RbSavePlain',
        'BorderChoiceSafe', 'BorderChoiceRisk', 'BtnChoiceOk', 'BtnChoiceCancel') {
        $found = $choiceDialog.FindName($name)
        if ($null -eq $found) { throw "The save dialog is missing a control named '$name'." }
        $c[$name] = $found
    }

    $c.TxtChoiceSummary.Text = if ($Count -eq 1) { '1 value will be written. Choose how it is protected.' }
    else { '{0} values will be written. Choose how they are protected.' -f $Count }
    $c.TxtChoicePath.Text = $EncryptedPath

    $toggle = {
        $plain = [bool]$c.RbSavePlain.IsChecked
        $c.BorderChoiceSafe.Visibility = if ($plain) { 'Collapsed' } else { 'Visible' }
        $c.BorderChoiceRisk.Visibility = if ($plain) { 'Visible' } else { 'Collapsed' }
        $c.BtnChoiceOk.Content = if ($plain) { 'Choose file and export' } else { 'Save' }
    }.GetNewClosure()
    & $toggle

    $c.RbSaveEncrypted.Add_Checked((Register-Handler $toggle))
    $c.RbSavePlain.Add_Checked((Register-Handler $toggle))

    # The answer rides on Tag so it survives the closure boundary.
    $choiceDialog.Tag = ''
    $c.BtnChoiceOk.Add_Click((Register-Handler {
                $choiceDialog.Tag = if ($c.RbSavePlain.IsChecked) { 'Plain' } else { 'Encrypted' }
                $choiceDialog.Close()
            }.GetNewClosure()))

    $null = $choiceDialog.ShowDialog()
    return [string]$choiceDialog.Tag
}

# Runs the chosen save, including the file picker for an unencrypted export.
# Returns the status text to show, or '' when the user backed out.
function Save-DefaultsWithChoice {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Table,
        [object]$Owner)

    $owningWindow = if ($null -eq $Owner) { $script:Window } else { $Owner }
    $encryptedPath = Get-DefaultsPath
    $choice = Show-SaveChoiceDialog -Count $Table.Count -EncryptedPath $encryptedPath -Owner $owningWindow
    if ($choice -eq 'Encrypted') {
        $saved = Save-ParameterDefaults -Path $encryptedPath -Table $Table
        return 'Saved and encrypted for this Windows account at ' + $saved
    }
    if ($choice -ne 'Plain') { return '' }

    $picker = New-Object Microsoft.Win32.SaveFileDialog
    $picker.Filter = 'Shareable defaults, unencrypted (*.json)|*.json|All files (*.*)|*.*'
    $picker.FileName = 'parameter-defaults.json'
    $picker.Title = 'Export parameter defaults, unencrypted'
    if ($picker.ShowDialog($owningWindow) -ne $true) { return '' }
    $saved = Save-ParameterDefaults -Path $picker.FileName -Table $Table -Plain
    return 'Exported UNENCRYPTED to ' + $saved
}

$script:XamlDefaultsDialog = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Parameter defaults" Height="620" Width="640" MinHeight="520" MinWidth="520"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        UseLayoutRounding="True" SnapsToDevicePixels="True"
        FontFamily="Segoe UI Variable Text, Segoe UI, Tahoma" FontSize="13"
        Background="{DynamicResource Bg.App}" Foreground="{DynamicResource Text.Primary}">
  <Grid Margin="18">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0" Margin="0,0,0,14">
      <TextBlock Text="Parameter defaults" Style="{DynamicResource Text.Subtitle}"/>
      <TextBlock x:Name="TxtDlgContext" Style="{DynamicResource Text.Caption}" TextWrapping="Wrap" Margin="0,3,0,0"/>
    </StackPanel>

    <StackPanel Grid.Row="1" Margin="0,0,0,10">
      <TextBlock Text="Parameter name" Style="{DynamicResource Text.Label}"/>
      <ComboBox x:Name="CmbDlgName" IsEditable="True" IsTextSearchEnabled="True"
                ToolTip="Names from the operation you are viewing, plus any you already saved"/>
    </StackPanel>

    <StackPanel Grid.Row="2" Margin="0,0,0,12">
      <TextBlock Text="Value" Style="{DynamicResource Text.Label}"/>
      <ComboBox x:Name="CmbDlgValue" IsEditable="True" IsTextSearchEnabled="True"
                ToolTip="Open the list to load values from Azure, or type one"/>
      <TextBlock x:Name="TxtDlgHint" Style="{DynamicResource Text.Caption}" TextWrapping="Wrap" Margin="0,5,0,0"/>
    </StackPanel>

    <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,0,0,12">
      <Button x:Name="BtnDlgSet" Content="Set value" Style="{DynamicResource Btn.Primary}" MinWidth="110"/>
      <Button x:Name="BtnDlgRemove" Content="Remove selected" Style="{DynamicResource Btn.Secondary}" Margin="8,0,0,0"/>
    </StackPanel>

    <Border Grid.Row="4" Style="{DynamicResource Card}" Padding="0">
      <Grid>
        <ListBox x:Name="LstDlgDefaults" BorderThickness="0" Background="Transparent"
                 ScrollViewer.HorizontalScrollBarVisibility="Disabled">
          <ListBox.ItemTemplate>
            <DataTemplate>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="18"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" Text="{Binding Marker}" ToolTip="{Binding Detail}"
                           Foreground="{DynamicResource State.Danger}" FontWeight="Bold"
                           VerticalAlignment="Center"/>
                <TextBlock Grid.Column="1" Text="{Binding Display}" ToolTip="{Binding Detail}"
                           TextTrimming="CharacterEllipsis" VerticalAlignment="Center"/>
              </Grid>
            </DataTemplate>
          </ListBox.ItemTemplate>
        </ListBox>
        <TextBlock x:Name="TxtDlgEmpty" Text="No defaults set yet." IsHitTestVisible="False"
                   HorizontalAlignment="Center" VerticalAlignment="Center"
                   Foreground="{DynamicResource Text.Tertiary}"/>
      </Grid>
    </Border>

    <Border Grid.Row="5" Background="{DynamicResource State.WarningBg}" CornerRadius="4" Padding="10,7" Margin="0,12,0,0">
      <TextBlock Style="{DynamicResource Text.Caption}" TextWrapping="Wrap"
                 Text="These values contain subscription IDs and other non-public identifiers. Save keeps a private copy encrypted with your Windows account, or exports an unencrypted copy you can share with your team."/>
    </Border>

    <Grid Grid.Row="6" Margin="0,14,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0" Orientation="Horizontal">
        <Button x:Name="BtnDlgLoad" Content="Load" Style="{DynamicResource Btn.Subtle}"/>
        <Button x:Name="BtnDlgSaveAs" Content="Save as" Style="{DynamicResource Btn.Subtle}" Margin="6,0,0,0"/>
        <Button x:Name="BtnDlgClear" Content="Clear all" Style="{DynamicResource Btn.Subtle}" Margin="6,0,0,0"/>
      </StackPanel>
      <StackPanel Grid.Column="1" Orientation="Horizontal">
        <Button x:Name="BtnDlgSave" Content="Save" Style="{DynamicResource Btn.Primary}" MinWidth="100"/>
        <Button x:Name="BtnDlgClose" Content="Close" Style="{DynamicResource Btn.Secondary}" Margin="8,0,0,0" IsCancel="True"/>
      </StackPanel>
    </Grid>
  </Grid>
</Window>
'@

function Show-DefaultsDialog {
    $dialog = New-GuiWindow -Markup $script:XamlDefaultsDialog
    $dialog.Owner = $script:Window
    # Share the main window's dictionary so styles and the active theme apply here too.
    $dialog.Resources = $script:Window.Resources

    $d = @{}
    foreach ($name in 'TxtDlgContext', 'CmbDlgName', 'CmbDlgValue', 'TxtDlgHint', 'BtnDlgSet', 'BtnDlgRemove',
        'LstDlgDefaults', 'TxtDlgEmpty', 'BtnDlgLoad', 'BtnDlgSaveAs', 'BtnDlgClear', 'BtnDlgSave', 'BtnDlgClose') {
        $found = $dialog.FindName($name)
        if ($null -eq $found) { throw "The defaults dialog is missing a control named '$name'." }
        $d[$name] = $found
    }

    # GetNewClosure rebinds $script: to the closure's own module, where these do not
    # exist, so both are captured as locals for every handler below.
    $app = $script:App
    $uiRef = $ui
    $stateRef = $script:DefaultsState
    # Built from its code point to keep the file pure ASCII.
    $bang = [string][char]0x0021

    $preset = $app.SelectedPreset
    $operationNames = @($app.ParamBoxes.Keys | Sort-Object)
    if ($null -ne $preset) {
        $d.TxtDlgContext.Text = 'Names from {0} are listed first. Values load from Azure for the operation you are viewing.' -f $preset.Name
    }
    else {
        $d.TxtDlgContext.Text = 'Select an operation first and its parameter names will be offered here with live values from Azure.'
    }

    foreach ($name in $operationNames) { $d.CmbDlgName.Items.Add($name) | Out-Null }
    foreach ($name in @($app.Defaults.Keys)) {
        if ($name -and $d.CmbDlgName.Items -notcontains $name) { $d.CmbDlgName.Items.Add($name) | Out-Null }
    }
    foreach ($name in @('subscriptionId', 'resourceGroupName', 'location')) {
        if ($d.CmbDlgName.Items -notcontains $name) { $d.CmbDlgName.Items.Add($name) | Out-Null }
    }

    $refresh = {
        $selectedName = ''
        if ($null -ne $d.LstDlgDefaults.SelectedItem) { $selectedName = [string]$d.LstDlgDefaults.SelectedItem.Name }
        $d.LstDlgDefaults.Items.Clear()
        foreach ($key in @($app.Defaults.Keys)) {
            if (-not $key) { continue }
            $verdict = Get-DefaultsStateFor -Name $key
            $row = [pscustomobject]@{
                Name    = [string]$key
                Value   = [string]$app.Defaults[$key]
                State   = [string]$verdict.State
                Detail  = [string]$verdict.Detail
                Display = '{0}  =  {1}' -f $key, $app.Defaults[$key]
                Marker  = $(if ([string]$verdict.State -eq 'Invalid') { $bang } else { '' })
            }
            $d.LstDlgDefaults.Items.Add($row) | Out-Null
            if ($selectedName -eq [string]$key) { $d.LstDlgDefaults.SelectedItem = $row }
        }
        $d.TxtDlgEmpty.Visibility = if ($d.LstDlgDefaults.Items.Count -eq 0) { 'Visible' } else { 'Collapsed' }
        $uiRef.TxtDefaults.Text = ConvertTo-DefaultsText -Table $app.Defaults
        $d.BtnDlgClose.ToolTip = if (Test-DefaultsHaveInvalid) { 'Fix or remove the values marked with an exclamation before closing.' } else { 'Close' }
    }.GetNewClosure()
    & $refresh

    $d.CmbDlgName.Add_SelectionChanged((Register-Handler {
                $name = [string]$d.CmbDlgName.Text
                if ($app.Defaults.Contains($name)) { $d.CmbDlgValue.Text = [string]$app.Defaults[$name] }
                $d.CmbDlgValue.Items.Clear()
                $d.CmbDlgValue.Tag = $null
                $d.TxtDlgHint.Text = if ($operationNames -contains $name) { 'Open the value list to load choices from Azure.' } else { '' }
            }.GetNewClosure()))

    $d.CmbDlgValue.Add_DropDownOpened((Register-Handler {
                param($comboSender, $eventArgs)
                $tag = $comboSender.Tag
                if ($null -ne $tag -and $tag.Loaded) { return }
                $name = [string]$d.CmbDlgName.Text
                if ([string]::IsNullOrWhiteSpace($name)) { $d.TxtDlgHint.Text = 'Choose a parameter name first.'; return }
                Update-ParameterChoices -Placeholder $name -Control $comboSender
            }.GetNewClosure()))

    $d.LstDlgDefaults.Add_SelectionChanged((Register-Handler {
                $row = $d.LstDlgDefaults.SelectedItem
                if ($null -eq $row) { return }
                $d.CmbDlgName.Text = [string]$row.Name
                $d.CmbDlgValue.Text = [string]$row.Value
                if ([string]$row.State -eq 'Invalid') { $d.TxtDlgHint.Text = [string]$row.Detail }
            }.GetNewClosure()))

    $d.BtnDlgSet.Add_Click((Register-Handler {
                $name = ([string]$d.CmbDlgName.Text).Trim()
                $value = (Get-ParamBoxValue -Control $d.CmbDlgValue).Trim()
                if ([string]::IsNullOrWhiteSpace($name)) { Show-Message -Text 'Enter a parameter name.' -Caption 'Parameter defaults' -Icon 'Warning'; return }
                if ($name -notmatch '^[A-Za-z0-9]+$') { Show-Message -Text 'A parameter name must be letters and digits only.' -Caption 'Parameter defaults' -Icon 'Warning'; return }
                if ([string]::IsNullOrWhiteSpace($value)) { Show-Message -Text 'Enter or choose a value.' -Caption 'Parameter defaults' -Icon 'Warning'; return }
                $app.Defaults[$name] = $value
                # An edited value is no longer whatever the last check concluded.
                $stateRef[$name] = @{ State = 'Unknown'; Detail = 'Not checked since it was edited.' }
                & $refresh
                Set-Status ('Default set for {0}' -f $name)
            }.GetNewClosure()))

    $d.BtnDlgRemove.Add_Click((Register-Handler {
                $row = $d.LstDlgDefaults.SelectedItem
                if ($null -eq $row) { return }
                $name = [string]$row.Name
                $app.Defaults.Remove($name)
                $stateRef.Remove($name)
                & $refresh
                Set-Status ('Removed default for {0}' -f $name)
            }.GetNewClosure()))

    $d.BtnDlgSave.Add_Click((Register-Handler {
                $status = Save-DefaultsWithChoice -Table $app.Defaults -Owner $dialog
                if ([string]::IsNullOrEmpty($status)) { return }
                $uiRef.TxtDefaultsPath.Text = $status
                Set-Status ('Saved {0} default value(s)' -f $app.Defaults.Count)
            }.GetNewClosure()))

    $d.BtnDlgSaveAs.Add_Click((Register-Handler {
                $dlg = New-Object Microsoft.Win32.SaveFileDialog
                $dlg.Filter = 'Encrypted defaults (*.dat)|*.dat|Plain JSON, unencrypted (*.json)|*.json'
                $dlg.FileName = 'parameter-defaults.dat'
                if ($dlg.ShowDialog($dialog) -ne $true) { return }
                $plain = ($dlg.FilterIndex -eq 2)
                $warning = if ($plain) { "You chose PLAIN JSON, which is NOT encrypted.`r`n`r`nAnyone who can read the file, including backup, sync, and search indexing, can read every value.`r`n`r`nContinue?" }
                else { "The file is encrypted with your Windows account.`r`n`r`nIt still contains values that identify your environment. Do not share it.`r`n`r`nContinue?" }
                if (-not (Confirm-Action -Text $warning -Caption 'Save parameter defaults')) { return }
                $saved = Save-ParameterDefaults -Path $dlg.FileName -Table $app.Defaults -Plain:$plain
                $uiRef.TxtDefaultsPath.Text = if ($plain) { 'Saved UNENCRYPTED to ' + $saved } else { 'Saved and encrypted to ' + $saved }
            }.GetNewClosure()))

    $d.BtnDlgLoad.Add_Click((Register-Handler {
                $dlg = New-Object Microsoft.Win32.OpenFileDialog
                $dlg.Filter = 'Defaults (*.dat;*.json)|*.dat;*.json|All files (*.*)|*.*'
                if ($dlg.ShowDialog($dialog) -ne $true) { return }
                $table = Import-ParameterDefaults -Path $dlg.FileName
                if ($null -eq $table) { return }
                Set-ParameterDefaults -Table $table
                & $refresh
                $uiRef.TxtDefaultsPath.Text = 'Loaded from ' + $dlg.FileName
            }.GetNewClosure()))

    $d.BtnDlgClear.Add_Click((Register-Handler {
                if (-not (Confirm-Action -Text 'Remove every saved default value?' -Caption 'Clear parameter defaults')) { return }
                Set-ParameterDefaults -Table ([ordered]@{})
                & $refresh
            }.GetNewClosure()))

    $d.BtnDlgClose.Add_Click((Register-Handler { $dialog.Close() }.GetNewClosure()))

    # Only a confirmed Invalid blocks. Unknown never does, so a value that was never
    # checkable, or a check that failed because the network was down, cannot trap the
    # user inside their own dialog.
    $dialog.Add_Closing((Register-Handler {
                param($closingSender, $closingArgs)
                if (-not (Test-DefaultsHaveInvalid)) { return }
                $bad = New-Object System.Collections.Generic.List[string]
                foreach ($key in @($app.Defaults.Keys)) {
                    if ([string](Get-DefaultsStateFor -Name $key).State -eq 'Invalid') { $bad.Add([string]$key) | Out-Null }
                }
                $closingArgs.Cancel = $true
                $d.TxtDlgContext.Text = 'Update or remove these before closing: ' + ($bad -join ', ')
                Show-Message -Caption 'Parameter defaults' -Icon 'Warning' -Text (
                    "These saved values do not exist in the current tenant:`r`n`r`n{0}`r`n`r`nSelect each one and either set a new value or remove it." -f ($bad -join "`r`n"))
            }.GetNewClosure()))

    Start-DefaultsValidation -Controls $d -Refresh $refresh

    $null = $dialog.ShowDialog()
    Set-ParameterDefaults -Table $script:App.Defaults
    $applied = Use-ParameterDefaults
    if ($applied -gt 0) { Set-Status ('Applied {0} default value(s) to the current operation' -f $applied) }
}

function Get-ParamBoxValue {
    param([AllowNull()][object]$Control)
    if ($null -eq $Control) { return '' }
    if ($Control -is [System.Windows.Controls.ComboBox]) {
        if ($Control.IsEditable) {
            # A control mid-load shows animated placeholder text, which is not a value.
            if ($script:App.LoadingControls.Contains($Control)) { return '' }
            $text = [string]$Control.Text
            $tag = $Control.Tag
            # Pickers can show a friendly label, so map it back to the value ARM needs.
            if ($null -ne $tag -and $null -ne $tag.Map -and $tag.Map.ContainsKey($text)) { return [string]$tag.Map[$text] }
            return $text
        }
        if ($null -ne $Control.SelectedItem) { return [string]$Control.SelectedItem }
        return ''
    }
    return [string]$Control.Text
}

function Start-ParamLoading {
    param([Parameter(Mandatory = $true)][System.Windows.Controls.ComboBox]$Control)
    if (-not $script:App.LoadingControls.Contains($Control)) { $script:App.LoadingControls.Add($Control) }
    $Control.IsDropDownOpen = $false
    if ($null -eq $script:App.LoadingTimer) {
        $timer = [System.Windows.Threading.DispatcherTimer]::new()
        $timer.Interval = [TimeSpan]::FromMilliseconds(180)
        $timer.Add_Tick((Register-Handler {
                    $script:App.LoadingPhase = ($script:App.LoadingPhase + 1) % 4
                    $suffix = '.' * $script:App.LoadingPhase
                    foreach ($control in @($script:App.LoadingControls)) { $control.Text = 'Loading' + $suffix }
                }))
        $script:App.LoadingTimer = $timer
    }
    $script:App.LoadingPhase = 0
    $Control.Text = 'Loading'
    $script:App.LoadingTimer.Start()
}

function Stop-ParamLoading {
    param([Parameter(Mandatory = $true)][System.Windows.Controls.ComboBox]$Control,
        [string]$RestoreText = '', [switch]$ReopenList)
    $null = $script:App.LoadingControls.Remove($Control)
    if ($script:App.LoadingControls.Count -eq 0 -and $null -ne $script:App.LoadingTimer) { $script:App.LoadingTimer.Stop() }
    $Control.Text = $RestoreText
    if ($ReopenList -and $Control.Items.Count -gt 0) { $Control.IsDropDownOpen = $true }
    Update-EffectiveRequest
}

# A placeholder's candidate values are whatever the collection immediately above it
# returns, so the lookup URL is the template truncated at that placeholder.
function Get-PlaceholderLookupPath {
    param([Parameter(Mandatory = $true)][string]$Placeholder)

    $preset = $script:App.SelectedPreset
    if ($null -eq $preset) { return $null }
    $template = [string]$preset.RelativePathTemplate
    $token = '{' + $Placeholder + '}'
    $index = $template.IndexOf($token, [System.StringComparison]::OrdinalIgnoreCase)
    if ($index -lt 1) { return $null }

    $prefix = $template.Substring(0, $index).TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($prefix)) { return $null }

    foreach ($match in [regex]::Matches($prefix, '\{([A-Za-z0-9]+)\}')) {
        $name = $match.Groups[1].Value
        $value = Get-ParamBoxValue -Control $script:App.ParamBoxes[$name]
        # Fall back to a saved default so the lookup still works from the defaults dialog.
        if ([string]::IsNullOrWhiteSpace($value) -and $script:App.Defaults.Contains($name)) {
            $value = [string]$script:App.Defaults[$name]
        }
        if ([string]::IsNullOrWhiteSpace($value)) { return @{ Missing = $name } }
        $prefix = $prefix.Replace($match.Value, [System.Uri]::EscapeDataString($value.Trim()))
    }
    return @{ Path = $prefix }
}

# A scope value such as resourceUri is a whole resource ID, so its separators must
# survive substitution. Each segment is escaped on its own rather than the whole value,
# which would turn the slashes into %2F and break the request.
function ConvertTo-ArmPathValue {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $trimmed = $Value.Trim()
    if (-not $trimmed.Contains('/')) { return [System.Uri]::EscapeDataString($trimmed) }
    # No leading separator: the template already has one before the placeholder, and
    # keeping the value's own would produce a doubled slash.
    $parts = @($trimmed -split '/' | Where-Object { $_ -ne '' } | ForEach-Object { [System.Uri]::EscapeDataString($_) })
    return ($parts -join '/')
}

# A scope placeholder is the whole prefix: the template begins with it, so there is no
# parent collection to list and the value is a resource ID rather than a name.
function Test-IsScopePlaceholder {
    param([Parameter(Mandatory = $true)][string]$Placeholder)
    $preset = $script:App.SelectedPreset
    if ($null -eq $preset) { return $false }
    $template = [string]$preset.RelativePathTemplate
    return $template.StartsWith('/{' + $Placeholder + '}', [System.StringComparison]::OrdinalIgnoreCase)
}

# Derives the ARM resource type a placeholder names, from the request template.
# A top-level type can be listed across the whole subscription; a nested one cannot,
# because the generic resources endpoint does not return child resources.
function Get-PlaceholderResourceType {
    param([Parameter(Mandatory = $true)][string]$Placeholder)

    $preset = $script:App.SelectedPreset
    if ($null -eq $preset) { return $null }
    $template = [string]$preset.RelativePathTemplate
    $token = '{' + $Placeholder + '}'
    $index = $template.IndexOf($token, [System.StringComparison]::OrdinalIgnoreCase)
    if ($index -lt 1) { return $null }

    $prefix = $template.Substring(0, $index).TrimEnd('/')
    $providerAt = $prefix.LastIndexOf('/providers/', [System.StringComparison]::OrdinalIgnoreCase)
    if ($providerAt -lt 0) { return $null }
    $segments = @($prefix.Substring($providerAt + 11) -split '/' | Where-Object { $_ })
    if ($segments.Count -lt 2) { return $null }

    # Drop the placeholders that name parent instances; what remains is the type path.
    $typeSegments = @($segments[1..($segments.Count - 1)] | Where-Object { $_ -notmatch '^\{.*\}$' })
    if ($typeSegments.Count -eq 0) { return $null }
    return [pscustomobject]@{
        ResourceType = $segments[0] + '/' + ($typeSegments -join '/')
        IsTopLevel   = ($typeSegments.Count -eq 1)
    }
}

# Choosing a resource that lives in a specific group fills that group in, so the user
# never has to know it beforehand.
function Set-RelatedParameterFromSelection {
    param([Parameter(Mandatory = $true)][System.Windows.Controls.ComboBox]$Control)
    if ($null -eq $Control.SelectedItem) { return }
    $tag = $Control.Tag
    if ($null -eq $tag) { return }
    $groupMap = Get-SafeProperty -InputObject $tag -Name 'GroupMap'
    if ($null -eq $groupMap) { return }
    $label = [string]$Control.SelectedItem
    if (-not $groupMap.Contains($label)) { return }
    $group = [string]$groupMap[$label]
    if ([string]::IsNullOrWhiteSpace($group)) { return }
    $target = $script:App.ParamBoxes['resourceGroupName']
    if ($null -eq $target) { return }
    if ((Get-ParamBoxValue -Control $target) -eq $group) { return }
    $target.Text = $group
    Set-Status ('Resource group set to {0} to match the resource you picked' -f $group)
}

# A child list is only valid for the parent it was loaded against, so changing a value
# discards every list that came from it. The typed text is kept; only the stale choices
# and the loaded flag go.
function Reset-DownstreamParameter {
    param([Parameter(Mandatory = $true)][string]$Placeholder)
    $preset = $script:App.SelectedPreset
    if ($null -eq $preset) { return }
    $template = [string]$preset.RelativePathTemplate
    $at = $template.IndexOf('{' + $Placeholder + '}', [System.StringComparison]::OrdinalIgnoreCase)
    if ($at -lt 0) { return }

    foreach ($match in [regex]::Matches($template, '\{([A-Za-z0-9]+)\}')) {
        if ($match.Index -le $at) { continue }
        $name = $match.Groups[1].Value
        $control = $script:App.ParamBoxes[$name]
        if ($null -eq $control -or -not ($control -is [System.Windows.Controls.ComboBox])) { continue }
        # Bumping the generation makes any load already in flight discard its result,
        # which would otherwise arrive holding values for the previous parent.
        $current = 0
        if ($script:App.ParamGeneration.ContainsKey($name)) { $current = [int]$script:App.ParamGeneration[$name] }
        $script:App.ParamGeneration[$name] = $current + 1
        if ($script:App.LoadingControls.Contains($control)) { continue }
        $kept = [string]$control.Text
        $control.Tag = $null
        $control.Items.Clear()
        $control.Text = $kept
    }
}

# Loads the next picker in the chain once its parents are known, so the user does not
# have to open each list in turn. One call, not a cascade: the worker is serial.
function Start-NextParameterLoad {
    param([Parameter(Mandatory = $true)][string]$Placeholder)
    if ($script:App.Busy) { return }
    $preset = $script:App.SelectedPreset
    if ($null -eq $preset -or $null -eq $script:App.Context) { return }
    $template = [string]$preset.RelativePathTemplate
    $at = $template.IndexOf('{' + $Placeholder + '}', [System.StringComparison]::OrdinalIgnoreCase)
    if ($at -lt 0) { return }

    foreach ($match in [regex]::Matches($template, '\{([A-Za-z0-9]+)\}')) {
        if ($match.Index -le $at) { continue }
        $name = $match.Groups[1].Value
        $control = $script:App.ParamBoxes[$name]
        if ($null -eq $control -or -not ($control -is [System.Windows.Controls.ComboBox])) { continue }
        if (-not $control.IsEditable) { continue }
        if ($control.Items.Count -gt 0) { continue }
        $lookup = Get-PlaceholderLookupPath -Placeholder $name
        if ($null -eq $lookup -or $lookup.ContainsKey('Missing')) { return }
        Update-ParameterChoices -Placeholder $name -Control $control -Quiet
        return
    }
}

function Get-ParameterLoadStamp {
    param([Parameter(Mandatory = $true)][string]$Placeholder)
    if ($script:App.ParamGeneration.ContainsKey($Placeholder)) { return [int]$script:App.ParamGeneration[$Placeholder] }
    return 0
}

# True when the parent this load was started for has changed since.
function Test-ParameterLoadStale {
    param([Parameter(Mandatory = $true)][string]$Placeholder, [Parameter(Mandatory = $true)][int]$Stamp)
    return ((Get-ParameterLoadStamp -Placeholder $Placeholder) -ne $Stamp)
}

function Update-ParameterChoices {
    param([Parameter(Mandatory = $true)][string]$Placeholder,
        [Parameter(Mandatory = $true)][System.Windows.Controls.ComboBox]$Control,
        [switch]$Quiet)

    if ($script:App.Busy) { return }
    if ($null -eq $script:App.Context) {
        if (-not $Quiet) { Set-Status 'Sign in to list available values.' }
        return
    }
    $previous = Get-ParamBoxValue -Control $Control
    # GetNewClosure rebinds $script:, so the separator has to be a captured local.
    $dot = $script:MiddleDot
    # Stamped now and re-checked on completion, so a result for a parent the user has
    # since changed is discarded instead of shown.
    $stamp = Get-ParameterLoadStamp -Placeholder $Placeholder
    $placeholderKey = $Placeholder

    if ($Placeholder -eq 'subscriptionId') {
        Start-ParamLoading -Control $Control
        Invoke-Worker -Script 'Get-ArmGuiSubscriptionChoice' -StatusText 'Listing subscriptions' -OnSuccess {
            param($result)
            $map = @{}
            $Control.Items.Clear()
            $selected = ''
            # Current subscription first so the active context is obvious.
            foreach ($subscription in (@($result) | Sort-Object @{ Expression = { -not $_.IsCurrent } }, Name)) {
                if (-not $subscription.Id) { continue }
                $label = '{0}  {1}  {2}' -f $subscription.Name, $dot, $subscription.Id
                if ($subscription.IsCurrent) { $label = $label + '   (current)' }
                $map[$label] = [string]$subscription.Id
                $Control.Items.Add($label) | Out-Null
                if ($subscription.IsCurrent) { $selected = $label }
            }
            $Control.Tag = [pscustomobject]@{ Loaded = ($Control.Items.Count -gt 0); Map = $map }
            if (-not $selected) {
                foreach ($entry in $map.Keys) { if ($map[$entry] -eq $previous) { $selected = $entry; break } }
            }
            if (-not $selected) { $selected = $previous }
            Stop-ParamLoading -Control $Control -RestoreText $selected -ReopenList
            Set-Status ('Listed {0} subscriptions' -f $Control.Items.Count)
        }.GetNewClosure() -OnFailure {
            param($message)
            Stop-ParamLoading -Control $Control -RestoreText $previous
            Set-Status ('Could not list subscriptions. ' + (ConvertTo-SafeErrorText $message)) -Kind 'Problem'
        }.GetNewClosure()
        return
    }

    $subscriptionId = Get-ParamBoxValue -Control $script:App.ParamBoxes['subscriptionId']
    if ([string]::IsNullOrWhiteSpace($subscriptionId) -and $script:App.Defaults.Contains('subscriptionId')) {
        $subscriptionId = [string]$script:App.Defaults['subscriptionId']
    }
    if ([string]::IsNullOrWhiteSpace($subscriptionId) -and $null -ne $script:App.Context) {
        $subscriptionId = [string]$script:App.Context.SubscriptionId
    }

    # A scope placeholder takes a whole resource ID, so it is offered the scopes that
    # exist rather than the names inside some parent collection.
    if ((Test-IsScopePlaceholder -Placeholder $Placeholder) -and -not [string]::IsNullOrWhiteSpace($subscriptionId)) {
        Start-ParamLoading -Control $Control
        Invoke-Worker -Script 'param($SubId) Get-ArmGuiScopeChoice -SubscriptionId $SubId' `
            -Parameters @{ SubId = $subscriptionId } -StatusText ('Listing scopes for ' + $Placeholder) -OnSuccess {
            param($result)
            if (Test-ParameterLoadStale -Placeholder $placeholderKey -Stamp $stamp) { Stop-ParamLoading -Control $Control -RestoreText $previous; return }
            $map = @{}
            $Control.Items.Clear()
            foreach ($row in @($result)) {
                if ($null -eq $row -or -not $row.Id) { continue }
                $label = [string]$row.Name
                if ($row.Kind) { $label = '{0}  {1}  {2}' -f $row.Name, $dot, $row.Kind }
                if ($row.Group) { $label = '{0}  {1}  {2}' -f $label, $dot, $row.Group }
                $map[$label] = [string]$row.Id
                $Control.Items.Add($label) | Out-Null
            }
            $Control.Tag = [pscustomobject]@{ Loaded = ($Control.Items.Count -gt 0); Map = $map }
            Stop-ParamLoading -Control $Control -RestoreText $previous -ReopenList
            if ($Control.Items.Count -eq 0) { Set-Status ('No scopes were returned for ' + $Placeholder) }
            else { Set-Status ('Listed {0} scopes for {1}' -f $Control.Items.Count, $Placeholder) }
        }.GetNewClosure() -OnFailure {
            param($message)
            Stop-ParamLoading -Control $Control -RestoreText $previous
            Set-Status ('Could not list scopes for ' + $Placeholder + '. ' + (ConvertTo-SafeErrorText $message)) -Kind 'Problem'
        }.GetNewClosure()
        return
    }

    # A top-level resource is listed across the whole subscription, so the user does not
    # have to know the resource group first. Picking one fills the group in afterwards.
    $typeInfo = Get-PlaceholderResourceType -Placeholder $Placeholder

    if ($null -ne $typeInfo -and $typeInfo.IsTopLevel -and -not [string]::IsNullOrWhiteSpace($subscriptionId)) {
        Start-ParamLoading -Control $Control
        Invoke-Worker -Script 'param($SubId,$ArmType) Get-ArmGuiResourceByType -SubscriptionId $SubId -ResourceType $ArmType' `
            -Parameters @{ SubId = $subscriptionId; ArmType = $typeInfo.ResourceType } `
            -StatusText ('Listing ' + $Placeholder) -OnSuccess {
            param($result)
            if (Test-ParameterLoadStale -Placeholder $placeholderKey -Stamp $stamp) { Stop-ParamLoading -Control $Control -RestoreText $previous; return }
            $map = @{}
            $groupMap = @{}
            $Control.Items.Clear()
            foreach ($row in @($result)) {
                if ($null -eq $row -or -not $row.Name) { continue }
                $label = [string]$row.Name
                if ($row.ResourceGroup) { $label = '{0}  {1}  {2}' -f $row.Name, $dot, $row.ResourceGroup }
                $map[$label] = [string]$row.Name
                $groupMap[$label] = [string]$row.ResourceGroup
                $Control.Items.Add($label) | Out-Null
            }
            # Loaded only when there is something to show, so an empty result does not
            # permanently stop the list from being retried.
            $Control.Tag = [pscustomobject]@{ Loaded = ($Control.Items.Count -gt 0); Map = $map; GroupMap = $groupMap }
            Stop-ParamLoading -Control $Control -RestoreText $previous -ReopenList
            if ($Control.Items.Count -eq 0) { Set-Status ('No {0} values exist in this subscription' -f $Placeholder) }
            else { Set-Status ('Listed {0} values for {1} across the subscription' -f $Control.Items.Count, $Placeholder) }
        }.GetNewClosure() -OnFailure {
            param($message)
            Stop-ParamLoading -Control $Control -RestoreText $previous
            Set-Status ('Could not list ' + $Placeholder + '. ' + (ConvertTo-SafeErrorText $message)) -Kind 'Problem'
        }.GetNewClosure()
        return
    }

    $lookup = Get-PlaceholderLookupPath -Placeholder $Placeholder
    if ($null -eq $lookup) {
        if (-not $Quiet) { Set-Status ("No collection endpoint exists for '$Placeholder'.") }
        return
    }
    if ($lookup.ContainsKey('Missing')) {
        if (-not $Quiet) { Set-Status ("Enter '{0}' first, then reopen this list." -f $lookup.Missing) }
        return
    }

    $apiVersion = [string]$ui.CmbApiVersion.Text
    if ($lookup.Path -notmatch '/providers/') { $apiVersion = '2021-04-01' }
    if ([string]::IsNullOrWhiteSpace($apiVersion)) { $apiVersion = '2021-04-01' }

    Start-ParamLoading -Control $Control
    Invoke-Worker -Script 'param($Path,$ApiVersion) Get-ArmGuiResourceNames -Path $Path -ApiVersion $ApiVersion' `
        -Parameters @{ Path = $lookup.Path; ApiVersion = $apiVersion } `
        -StatusText ('Listing ' + $Placeholder) -OnSuccess {
        param($result)
        if (Test-ParameterLoadStale -Placeholder $placeholderKey -Stamp $stamp) { Stop-ParamLoading -Control $Control -RestoreText $previous; return }
        $Control.Items.Clear()
        foreach ($name in @($result)) {
            if ($null -eq $name) { continue }
            $Control.Items.Add([string]$name) | Out-Null
        }
        $Control.Tag = [pscustomobject]@{ Loaded = ($Control.Items.Count -gt 0); Map = @{} }
        Stop-ParamLoading -Control $Control -RestoreText $previous -ReopenList
        if ($Control.Items.Count -eq 0) { Set-Status ('No values were returned for ' + $Placeholder) }
        else { Set-Status ('Listed {0} values for {1}' -f $Control.Items.Count, $Placeholder) }
    }.GetNewClosure() -OnFailure {
        param($message)
        Stop-ParamLoading -Control $Control -RestoreText $previous
        Set-Status ('Could not list ' + $Placeholder + '. ' + (ConvertTo-SafeErrorText $message)) -Kind 'Problem'
    }.GetNewClosure()
}

function New-ParameterInput {
    param([Parameter(Mandatory = $true)][string]$Placeholder, [AllowNull()][object]$Preset)

    if ($Placeholder -eq 'verificationType') {
        $fixed = [System.Windows.Controls.ComboBox]::new()
        foreach ($value in @('Domain', 'SPF', 'DKIM', 'DKIM2', 'DMARC')) { $fixed.Items.Add($value) | Out-Null }
        $fixed.SelectedIndex = 0
        return $fixed
    }

    # Editable so a value can still be typed when the account cannot list the collection.
    $editor = [System.Windows.Controls.ComboBox]::new()
    $editor.IsEditable = $true
    $editor.IsTextSearchEnabled = $true
    $editor.StaysOpenOnEdit = $true
    $editor.ToolTip = 'Open the list to load values from Azure, or type one.'
    if ($null -ne $Preset) {
        $example = Get-SafeProperty -InputObject $Preset.ExampleParameters -Name $Placeholder
        if ($example) { $editor.ToolTip = 'Open the list to load values from Azure, or type one. Example: ' + [string]$example }
    }
    if ($Placeholder -eq 'subscriptionId') {
        $context = $script:App.Context
        if ($null -ne $context -and $context.SubscriptionId) { $editor.Text = [string]$context.SubscriptionId }
    }
    # An explicit default outranks the ambient context.
    if ($script:App.Defaults.Contains($Placeholder)) { $editor.Text = [string]$script:App.Defaults[$Placeholder] }
    $captured = $Placeholder
    $editor.Add_DropDownOpened((Register-Handler {
                param($comboSender, $eventArgs)
                $tag = $comboSender.Tag
                if ($null -ne $tag -and $tag.Loaded) { return }
                Update-ParameterChoices -Placeholder $captured -Control $comboSender
            }.GetNewClosure()))
    $editor.Add_SelectionChanged((Register-Handler {
                param($comboSender, $eventArgs)
                if ($null -eq $comboSender.SelectedItem) { return }
                Set-RelatedParameterFromSelection -Control $comboSender
            }.GetNewClosure()))
    # Picking a value invalidates everything below it, then pulls the next list in.
    $editor.Add_SelectionChanged((Register-Handler {
                param($comboSender, $eventArgs)
                if ($null -eq $comboSender.SelectedItem) { return }
                Reset-DownstreamParameter -Placeholder $captured
                Start-NextParameterLoad -Placeholder $captured
            }.GetNewClosure()))
    return $editor
}

# Builds one labelled parameter row and registers its editor in ParamBoxes.
function Add-ParameterRow {
    param([Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$Preset,
        [bool]$IsRequired = $false,
        [string]$InitialValue = '')

    $panel = [System.Windows.Controls.StackPanel]::new()
    $panel.Margin = [System.Windows.Thickness]::new(0, 0, 0, 10)

    $label = [System.Windows.Controls.TextBlock]::new()
    $label.Text = if ($IsRequired) { $Name + '  (required)' } else { $Name }
    $label.FontSize = 12
    $label.FontWeight = 'SemiBold'
    $label.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
    $label.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Text.Secondary')

    $editor = New-ParameterInput -Placeholder $Name -Preset $Preset
    [System.Windows.Automation.AutomationProperties]::SetName($editor, $Name)
    # Seeded before the handlers attach so restoring a value raises no change event.
    if (-not [string]::IsNullOrEmpty($InitialValue)) { $editor.Text = $InitialValue }

    if ($editor -is [System.Windows.Controls.TextBox]) {
        $editor.Add_TextChanged((Register-Handler { Update-EffectiveRequest }))
    }
    elseif ($editor.IsEditable) {
        $editor.Add_SelectionChanged((Register-Handler { Update-EffectiveRequest }))
        $editor.AddHandler([System.Windows.Controls.Primitives.TextBoxBase]::TextChangedEvent,
            [System.Windows.Controls.TextChangedEventHandler](Register-Handler { Update-EffectiveRequest }))
    }
    else { $editor.Add_SelectionChanged((Register-Handler { Update-EffectiveRequest })) }

    $panel.Children.Add($label) | Out-Null
    $panel.Children.Add($editor) | Out-Null
    $ui.PnlPresetParams.Items.Add($panel) | Out-Null
    $script:App.ParamBoxes[$Name] = $editor
}

function Select-Preset {
    param([Parameter(Mandatory = $true)][object]$Preset)
    $script:App.SelectedPreset = $Preset
    $script:App.SelectedDiscovered = $null
    $script:App.ParamBoxes = @{}
    Set-WelcomeVisible -Visible $false
    Update-DocsLink -Operation $Preset
    $ui.BorderProvenance.Visibility = 'Collapsed'
    $ui.PanelScope.Visibility = 'Collapsed'
    $ui.TxtPresetName.Text = $Preset.Name
    $ui.TxtPresetDesc.Text = $Preset.Description
    $ui.TxtPresetPath.Text = $Preset.RelativePathTemplate
    $ui.PnlPresetParams.Items.Clear()

    $notes = @($Preset.Notes)
    if ($notes.Count -gt 0) {
        $ui.TxtPresetNotes.Text = ($notes -join '  ')
        $ui.TxtPresetNotes.Visibility = 'Visible'
    }
    else { $ui.TxtPresetNotes.Visibility = 'Collapsed' }

    $required = @($Preset.RequiredParameters)
    $placeholders = Get-PresetPlaceholders -Template $Preset.RelativePathTemplate
    $all = New-Object System.Collections.Generic.List[string]
    foreach ($n in $placeholders) { if (-not $all.Contains($n)) { $all.Add($n) } }
    foreach ($n in $required) { if (-not $all.Contains($n)) { $all.Add($n) } }
    foreach ($n in @($Preset.OptionalParameters)) { if (-not $all.Contains($n)) { $all.Add($n) } }

    foreach ($paramName in $all) {
        Add-ParameterRow -Name $paramName -Preset $Preset -IsRequired ($required -contains $paramName)
    }

    # Reflect preset defaults without marking them as user overrides.
    $ui.CmbMethod.SelectedItem = $Preset.Method
    $ui.CmbApiVersion.Items.Clear()
    foreach ($v in @($Preset.KnownApiVersions)) { $ui.CmbApiVersion.Items.Add($v) | Out-Null }
    $ui.CmbApiVersion.Text = $Preset.DefaultApiVersion

    if ($Preset.HasDefaultBody -and ([string](Get-SafeProperty -InputObject $Preset -Name 'Source') -ne 'Extended')) {
        $ui.TxtBodyHint.Text = 'This operation builds its request body automatically from the parameters above. Supplying a body here replaces it.'
    }
    elseif ($Preset.HasDefaultBody) {
        $ui.TxtBodyHint.Text = 'This operation needs a JSON body. Use Insert example for a starting point.'
    }
    elseif ($Preset.Method -in @('POST', 'PUT', 'PATCH')) {
        $ui.TxtBodyHint.Text = 'This operation usually requires a JSON body.'
    }
    else { $ui.TxtBodyHint.Text = '' }

    Update-MethodChip
    Set-Status ('Selected {0}' -f $Preset.Name)
}

# ==============================================================================
# REGION 13  Request assembly
# ==============================================================================

function Get-RequestMode {
    if ($ui.RbPath.IsChecked -eq $true) { return 'Path' }
    if ($ui.RbUri.IsChecked -eq $true) { return 'Uri' }
    return 'Preset'
}

function Get-EffectiveMethod {
    $mode = Get-RequestMode
    if ($mode -eq 'Preset') {
        $preset = $script:App.SelectedPreset
        if ($null -ne $preset -and $ui.ChkOverrideMethod.IsChecked -ne $true) { return [string]$preset.Method }
    }
    $selected = $ui.CmbMethod.SelectedItem
    if ($null -eq $selected) { return 'GET' }
    return [string]$selected
}

function ConvertFrom-HeaderText {
    param([string]$Text)
    $table = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return $table }
    foreach ($line in ($Text -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $index = $line.IndexOf(':')
        if ($index -lt 1) { throw "Header line '$line' is not in 'Name: Value' format." }
        $name = $line.Substring(0, $index).Trim()
        $value = $line.Substring($index + 1).Trim()
        if ([string]::IsNullOrWhiteSpace($name)) { throw 'A header name cannot be empty.' }
        $table[$name] = $value
    }
    return $table
}

function Build-RequestArguments {
    $mode = Get-RequestMode
    $request = @{}

    if ($mode -eq 'Preset') {
        $preset = $script:App.SelectedPreset
        if ($null -eq $preset) { throw 'Select an operation from the list first.' }

        $operationParameters = @{}
        foreach ($key in $script:App.ParamBoxes.Keys) {
            $value = Get-ParamBoxValue -Control $script:App.ParamBoxes[$key]
            if (-not [string]::IsNullOrWhiteSpace($value)) { $operationParameters[$key] = $value.Trim() }
        }

        $isExtended = ([string](Get-SafeProperty -InputObject $preset -Name 'Source') -eq 'Extended')
        if ($isExtended) {
            # The core resolves -Operation only against its own hardcoded catalog, so
            # these are sent as a resolved path instead.
            $context = $script:App.Context
            if (-not $operationParameters.ContainsKey('subscriptionId') -and $null -ne $context -and $context.SubscriptionId) {
                $operationParameters['subscriptionId'] = [string]$context.SubscriptionId
            }
            $path = [string]$preset.RelativePathTemplate
            foreach ($match in [regex]::Matches($path, '\{([A-Za-z0-9]+)\}')) {
                $name = $match.Groups[1].Value
                if (-not $operationParameters.ContainsKey($name)) { throw "The operation parameter '$name' is required." }
                $path = $path.Replace($match.Value, (ConvertTo-ArmPathValue -Value ([string]$operationParameters[$name])))
            }
            $request['RelativePath'] = $path
            $request['Method'] = if ($ui.ChkOverrideMethod.IsChecked -eq $true) { [string]$ui.CmbMethod.SelectedItem } else { [string]$preset.Method }
            $apiVersion = [string]$ui.CmbApiVersion.Text
            if ([string]::IsNullOrWhiteSpace($apiVersion)) { $apiVersion = [string]$preset.DefaultApiVersion }
            if ([string]::IsNullOrWhiteSpace($apiVersion)) { throw 'An api-version is required for this operation.' }
            $request['ApiVersion'] = $apiVersion.Trim()
        }
        else {
            $request['Operation'] = [string]$preset.Name
            foreach ($required in @($preset.RequiredParameters)) {
                if ($required -eq 'subscriptionId') { continue }   # falls back to the signed-in context
                if (-not $operationParameters.ContainsKey($required)) {
                    throw "The operation parameter '$required' is required."
                }
            }
            # The core rejects OperationParameters unless Operation is also set.
            if ($operationParameters.Count -gt 0) { $request['OperationParameters'] = $operationParameters }
            if ($ui.ChkOverrideMethod.IsChecked -eq $true) { $request['Method'] = [string]$ui.CmbMethod.SelectedItem }
            if ($ui.ChkOverrideApiVersion.IsChecked -eq $true) {
                $apiVersion = [string]$ui.CmbApiVersion.Text
                if ([string]::IsNullOrWhiteSpace($apiVersion)) { throw 'Enter an api-version or clear the override.' }
                $request['ApiVersion'] = $apiVersion.Trim()
            }
        }
    }
    elseif ($mode -eq 'Path') {
        $path = [string]$ui.TxtRelativePath.Text
        if ([string]::IsNullOrWhiteSpace($path)) { throw 'Enter a relative ARM path.' }
        $path = $path.Trim()
        if ($path -match '(^|/)\.\.(/|$)') { throw 'The relative path cannot contain a parent-directory segment.' }
        if ($path -match '[\r\n]') { throw 'The relative path cannot contain a line break.' }
        $request['RelativePath'] = $path
        $request['Method'] = [string]$ui.CmbMethod.SelectedItem
        $apiVersion = [string]$ui.CmbApiVersion.Text
        if (-not [string]::IsNullOrWhiteSpace($apiVersion)) { $request['ApiVersion'] = $apiVersion.Trim() }
    }
    else {
        $uriText = [string]$ui.TxtUri.Text
        if ([string]::IsNullOrWhiteSpace($uriText)) { throw 'Enter an absolute HTTPS URI.' }
        $parsed = $null
        if (-not [System.Uri]::TryCreate($uriText.Trim(), [System.UriKind]::Absolute, [ref]$parsed)) {
            throw 'The URI could not be parsed as an absolute URI.'
        }
        if ($parsed.Scheme -ne 'https') { throw 'Only HTTPS URIs are supported.' }
        if (-not [string]::IsNullOrEmpty($parsed.UserInfo)) { throw 'The URI must not contain user information.' }
        $request['Uri'] = $parsed
        $request['Method'] = [string]$ui.CmbMethod.SelectedItem
        $apiVersion = [string]$ui.CmbApiVersion.Text
        if (-not [string]::IsNullOrWhiteSpace($apiVersion)) { $request['ApiVersion'] = $apiVersion.Trim() }
    }

    # Body
    if ($ui.RbBodyInline.IsChecked -eq $true) {
        $bodyText = [string]$ui.TxtBody.Text
        if ([string]::IsNullOrWhiteSpace($bodyText)) { throw 'The inline body is empty. Choose None or enter JSON.' }
        try { $null = $bodyText | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "The request body is not valid JSON. $($_.Exception.Message)" }
        $request['Body'] = $bodyText
    }
    elseif ($ui.RbBodyFile.IsChecked -eq $true) {
        $bodyFile = [string]$ui.TxtBodyFile.Text
        if ([string]::IsNullOrWhiteSpace($bodyFile)) { throw 'Choose a body file or select None.' }
        if (-not (Test-Path -LiteralPath $bodyFile -PathType Leaf)) { throw "The body file '$bodyFile' does not exist." }
        $request['BodyFile'] = $bodyFile
    }

    # Headers
    $headers = ConvertFrom-HeaderText -Text ([string]$ui.TxtHeaders.Text)
    if ($headers.Count -gt 0) { $request['Headers'] = $headers }

    # Output file, constrained to a leaf name inside the package Output folder.
    $outputFile = [string]$ui.TxtOutputFile.Text
    if (-not [string]::IsNullOrWhiteSpace($outputFile)) {
        $outputFile = $outputFile.Trim()
        $leaf = [System.IO.Path]::GetFileName($outputFile)
        if ($leaf -ne $outputFile -or [string]::IsNullOrWhiteSpace($leaf)) {
            throw 'Enter a file name only. The response is always written inside the package Output folder.'
        }
        if ($outputFile.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            throw 'The output file name contains invalid characters.'
        }
        $request['OutputFile'] = $outputFile
    }

    if ($ui.ChkRawOutput.IsChecked -eq $true) { $request['RawOutput'] = [switch]$true }
    if ($ui.ChkNoWait.IsChecked -eq $true) { $request['NoWait'] = [switch]$true }

    $pollInterval = 0
    if ([int]::TryParse([string]$ui.TxtPollInterval.Text, [ref]$pollInterval) -and $pollInterval -ge 1 -and $pollInterval -le 3600) {
        $request['PollIntervalSeconds'] = $pollInterval
    }
    $timeout = 0
    if ([int]::TryParse([string]$ui.TxtTimeout.Text, [ref]$timeout) -and $timeout -ge 1 -and $timeout -le 604800) {
        $request['LongRunningTimeoutSeconds'] = $timeout
    }

    return $request
}

function Get-RequestSummary {
    param([hashtable]$Request)
    $method = Get-EffectiveMethod
    $target = ''
    $probe = ''
    if ($Request.ContainsKey('Operation')) {
        $target = 'Operation ' + $Request['Operation']
        $preset = $script:App.SelectedPreset
        if ($null -ne $preset) { $probe = [string]$preset.RelativePathTemplate }
    }
    elseif ($Request.ContainsKey('RelativePath')) { $target = [string]$Request['RelativePath']; $probe = $target }
    elseif ($Request.ContainsKey('Uri')) { $target = [string]$Request['Uri']; $probe = $target }
    return @{ Method = $method; Target = $target; SecretProbe = $probe }
}

# Resource Manager hosts per cloud. Exact match or a true subdomain only, so a
# lookalike such as management.azure.com.example.net cannot capture the token.
$script:ArmHosts = @(
    'management.azure.com', 'management.usgovcloudapi.net', 'management.chinacloudapi.cn',
    'management.azure.microsoft.scloud', 'management.azure.eaglex.ic.gov', 'management.core.windows.net'
)

function Test-KnownArmHost {
    param([Parameter(Mandatory = $true)][string]$DnsHost)
    foreach ($known in $script:ArmHosts) {
        if ([string]::Equals($DnsHost, $known, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($DnsHost.EndsWith('.' + $known, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Confirm-Request {
    param([hashtable]$Request)

    $summary = Get-RequestSummary -Request $Request
    $method = $summary.Method
    $context = $script:App.Context

    # Non-Resource-Manager destinations receive an ARM access token.
    if ($Request.ContainsKey('Uri')) {
        $uri = [System.Uri]$Request['Uri']
        if (-not (Test-KnownArmHost -DnsHost $uri.DnsSafeHost)) {
            $text = "The host below is not a known Azure Resource Manager endpoint.`r`n`r`n" +
            "Host: $($uri.DnsSafeHost)`r`n`r`n" +
            "An Azure Resource Manager access token may be sent to this host. Continue only if you trust it.`r`n`r`nSend the request?"
            if (-not (Confirm-Action -Text $text -Caption 'Untrusted destination')) { return $false }
        }
    }

    if ($method -in @('DELETE', 'PUT', 'PATCH', 'POST')) {
        # Without a resolved context the dialog cannot name the blast radius, so refuse rather than guess.
        if ($null -eq $context) {
            Show-Message -Text 'Sign in before sending a request that can change a resource. The active tenant and subscription must be known before this is confirmed.' -Caption 'Sign in required' -Icon 'Warning'
            return $false
        }
        $verb = switch ($method) {
            'DELETE' { 'PERMANENTLY DELETE' }
            'PUT' { 'CREATE OR REPLACE' }
            'PATCH' { 'MODIFY' }
            default { 'RUN AN ACTION AGAINST' }
        }
        $account = if ($context.Account) { [string]$context.Account } else { 'unknown account' }
        $tenant = if ($context.TenantId) { [string]$context.TenantId } else { 'unknown tenant' }
        $subscription = if ($context.SubscriptionName) { '{0} ({1})' -f $context.SubscriptionName, $context.SubscriptionId }
        elseif ($context.SubscriptionId) { [string]$context.SubscriptionId }
        else { 'no subscription selected' }
        $environment = if ($context.Environment) { [string]$context.Environment } else { 'unknown cloud' }

        # An inferred path can be well-formed and still address the wrong thing, so the
        # confirmation has to say which kind of path this is.
        $provenance = ''
        if ((Get-RequestMode) -eq 'Preset') {
            $discovered = $script:App.SelectedDiscovered
            if ($null -ne $discovered -and
                [string](Get-SafeProperty -InputObject $discovered -Name 'RouteSource') -ne 'Documented') {
                $provenance = "This URL was inferred from RBAC metadata, not from published documentation.`r`n" +
                "Azure acts on the exact URL above. Confirm it is the resource you mean.`r`n`r`n"
            }
        }

        $text = "You are about to $verb a resource.`r`n`r`n" +
        "Method:        $method`r`n" +
        "Target:        $($summary.Target)`r`n`r`n" +
        $provenance +
        "Cloud:         $environment`r`n" +
        "Tenant:        $tenant`r`n" +
        "Subscription:  $subscription`r`n" +
        "Signed in as:  $account`r`n`r`n" +
        'Confirm this is the intended environment. Continue?'
        if (-not (Confirm-Action -Text $text -Caption ('Confirm ' + $method))) { return $false }
    }
    return $true
}

function Get-CliPreview {
    param([hashtable]$Request)
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('.\ArmClient-PS.ps1')
    foreach ($key in ($Request.Keys | Sort-Object)) {
        $value = $Request[$key]
        if ($value -is [System.Management.Automation.SwitchParameter] -or $value -is [bool]) {
            if ($value) { $parts.Add('-' + $key) }
            continue
        }
        if ($value -is [hashtable]) {
            $pairs = @($value.Keys | Sort-Object | ForEach-Object { "{0}='{1}'" -f $_, ([string]$value[$_] -replace "'", "''") })
            $parts.Add(('-{0} @{{ {1} }}' -f $key, ($pairs -join '; ')))
            continue
        }
        $text = [string]$value
        $parts.Add(('-{0} ''{1}''' -f $key, ($text -replace "'", "''")))
    }
    $environment = [string]$ui.CmbEnvironment.SelectedItem
    if ($environment -and $environment -ne 'AzureCloud') { $parts.Add(("-Environment '{0}'" -f $environment)) }
    return ($parts -join ' `' + [Environment]::NewLine + '  ')
}

# ==============================================================================
# REGION 14  Context presentation
# ==============================================================================

# The Azure context carries only the tenant GUID, so directory names come from a
# separate listing and are cached for the session. The GUID stands in until one arrives.
function Set-TenantNameCache {
    param([object[]]$Tenants)
    foreach ($tenant in @($Tenants)) {
        if ($null -eq $tenant) { continue }
        $id = [string](Get-SafeProperty -InputObject $tenant -Name 'Id')
        $name = [string](Get-SafeProperty -InputObject $tenant -Name 'Name')
        if ($id -and $name) { $script:App.TenantNames[$id] = $name }
    }
}

function Get-TenantLabel {
    param([AllowEmptyString()][string]$TenantId)
    if ([string]::IsNullOrWhiteSpace($TenantId)) { return 'unknown' }
    $name = [string]$script:App.TenantNames[$TenantId]
    if ([string]::IsNullOrWhiteSpace($name)) { return $TenantId }
    return '{0} ({1})' -f $name, $TenantId
}

# Cosmetic, so an account that cannot list tenants keeps the GUID and sees no error.
function Start-TenantNameLookup {
    $context = $script:App.Context
    if ($null -eq $context) { return }
    $tenantId = [string]$context.TenantId
    if (-not $tenantId -or $script:App.TenantNames.ContainsKey($tenantId)) { return }

    $restore = [string]$ui.TxtStatus.Text
    if ([string]::IsNullOrWhiteSpace($restore)) { $restore = 'Signed in' }
    Invoke-Worker -Script 'Get-ArmGuiTenant' -StatusText $restore -OnSuccess {
        param($result)
        Set-TenantNameCache -Tenants @($result)
        Update-ContextBanner
        Set-Status $restore
    }.GetNewClosure() -OnFailure {
        param($message)
        Set-Status $restore
    }.GetNewClosure()
}

function Update-ContextBanner {
    $context = $script:App.Context
    Update-SendAvailability

    if ($null -eq $context) {
        $ui.TxtEnvChip.Text = 'NOT SIGNED IN'
        $ui.TxtContext.Text = 'Sign in to select a tenant and subscription.'
        $ui.BorderEnvChip.Background = $script:Window.FindResource('State.Neutral')
        $ui.TxtEnvChip.Foreground = [System.Windows.Media.Brushes]::White
        $ui.BorderContext.Background = $script:Window.FindResource('State.NeutralBg')
        $ui.BtnSignOut.IsEnabled = $false
        $ui.BtnTenant.IsEnabled = $false
        return
    }

    # Always report the cloud of the ACTIVE context, never the dropdown, which the
    # user can change after signing in.
    $environment = if ($context.Environment) { [string]$context.Environment } else { 'unknown' }
    $ui.BtnSignOut.IsEnabled = -not $script:App.Busy
    $ui.BtnTenant.IsEnabled = -not $script:App.Busy
    $ui.TxtEnvChip.Text = $environment.ToUpperInvariant()

    $subscription = if ($context.SubscriptionName) { '{0}  ({1})' -f $context.SubscriptionName, $context.SubscriptionId }
    elseif ($context.SubscriptionId) { [string]$context.SubscriptionId }
    else { 'no subscription selected' }
    $ui.TxtContext.Text = '{0}     Tenant {1}     Subscription {2}' -f $context.Account, (Get-TenantLabel -TenantId $context.TenantId), $subscription

    $selectedEnvironment = [string]$ui.CmbEnvironment.SelectedItem
    if ($selectedEnvironment -and $selectedEnvironment -ne $environment) {
        $ui.TxtContext.Text = '{0}     (the {1} selection applies to the next sign-in)' -f $ui.TxtContext.Text, $selectedEnvironment
    }
    # The banner ellipses on a narrow window, so the full value stays reachable.
    $ui.TxtContext.ToolTip = $ui.TxtContext.Text

    if ($environment -eq 'AzureCloud') {
        $ui.BorderEnvChip.Background = $script:Window.FindResource('Accent.Default')
        $ui.TxtEnvChip.Foreground = $script:Window.FindResource('Text.OnAccent')
        $ui.BorderContext.Background = $script:Window.FindResource('Accent.Subtle')
    }
    else {
        # Sovereign and national clouds stay visually distinct at all times.
        $ui.BorderEnvChip.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString('#8F4B00'))
        $ui.TxtEnvChip.Foreground = [System.Windows.Media.Brushes]::White
        $ui.BorderContext.Background = $script:Window.FindResource('State.WarningBg')
    }
}

# ==============================================================================
# REGION 15  Response presentation
# ==============================================================================

# Drops any retained response material so a previous tenant's payload cannot
# outlive the request that produced it.
function Clear-ResponseState {
    Hide-Reveal
    $script:App.RawResponse = ''
    $script:App.RedactedText = ''
    $script:App.ResponseIsSecret = $false
    $ui.TxtResponse.Clear()
    $ui.TxtResponseEmpty.Visibility = 'Visible'
    $ui.TxtResponseHeaders.Clear()
    $ui.BtnReveal.IsEnabled = $false
    $ui.BtnCopyResponse.IsEnabled = $false
    $ui.BtnSaveResponse.IsEnabled = $false
    $ui.BorderRedactNotice.Visibility = 'Collapsed'
}

function Show-Response {
    param([string]$Raw, [string]$Redacted, [string]$Target)

    $script:App.RawResponse = $Raw
    $script:App.RedactedText = $Redacted
    $script:App.Revealed = $false

    $isSecretPath = ($Target -match $script:SecretPathPattern)
    $wasRedacted = ($Raw -ne $Redacted)
    $script:App.ResponseIsSecret = ($isSecretPath -or $wasRedacted)

    Set-ResponseText -Text $Redacted
    Set-RevealLock -Locked $false
    $ui.BtnReveal.Content = 'Reveal raw'
    $ui.BtnReveal.IsEnabled = $script:App.ResponseIsSecret
    $ui.BtnCopyResponse.IsEnabled = $true
    $ui.BtnSaveResponse.IsEnabled = $true

    if ($script:App.ResponseIsSecret) {
        $ui.BorderRedactNotice.Visibility = 'Visible'
        $ui.TxtRedactNotice.Text = if ($isSecretPath) {
            'This operation returns credentials. Values are redacted. Use Reveal raw for a time-limited view; copy and save always use the redacted text.'
        }
        else {
            'Sensitive values in this response are redacted. Use Reveal raw for a time-limited view; copy and save always use the redacted text.'
        }
    }
    else {
        $ui.BorderRedactNotice.Visibility = 'Collapsed'
    }
}

# While raw content is on screen, suppress copy and cut so Ctrl+C cannot defeat
# the redacted-only copy and save paths.
function Set-RevealLock {
    param([bool]$Locked)
    $box = $ui.TxtResponse
    if ($Locked) {
        if ($null -eq $script:App.RevealBlocker) {
            $script:App.RevealBlocker = [System.Windows.Input.ExecutedRoutedEventHandler] {
                param($blockSender, $blockArgs)
                if ($blockArgs.Command -eq [System.Windows.Input.ApplicationCommands]::Copy -or
                    $blockArgs.Command -eq [System.Windows.Input.ApplicationCommands]::Cut) {
                    $blockArgs.Handled = $true
                }
            }
        }
        [System.Windows.Input.CommandManager]::AddPreviewExecutedHandler($box, $script:App.RevealBlocker)
        $box.ContextMenu = $null
    }
    elseif ($null -ne $script:App.RevealBlocker) {
        [System.Windows.Input.CommandManager]::RemovePreviewExecutedHandler($box, $script:App.RevealBlocker)
    }
}

function Hide-Reveal {
    if (-not $script:App.Revealed) { return }
    $script:App.Revealed = $false
    Set-ResponseText -Text $script:App.RedactedText
    Set-RevealLock -Locked $false
    $ui.BtnReveal.Content = 'Reveal raw'
    if ($null -ne $script:App.RevealTimer) { $script:App.RevealTimer.Stop() }
    Set-Status 'Raw view hidden'
}

# ==============================================================================
# REGION 16  Event wiring
# ==============================================================================

function Register-Handler {
    param([Parameter(Mandatory = $true)][scriptblock]$Body)
    # Every handler is wrapped so a failure surfaces as a dialog instead of
    # terminating the dispatcher.
    return {
        param($eventSender, $eventArgs)
        try { & $Body $eventSender $eventArgs }
        catch { Show-Message -Text (ConvertTo-SafeErrorText $_.Exception.Message) -Caption 'Error' -Icon 'Error' }
    }.GetNewClosure()
}

foreach ($method in @('GET', 'POST', 'PUT', 'PATCH', 'DELETE')) { $ui.CmbMethod.Items.Add($method) | Out-Null }
$ui.CmbMethod.SelectedIndex = 0
foreach ($environment in $script:Environments) { $ui.CmbEnvironment.Items.Add($environment) | Out-Null }
$ui.CmbEnvironment.SelectedIndex = 0

$ui.CmbMethod.Add_SelectionChanged((Register-Handler { Update-MethodChip }))
$ui.ChkOverrideMethod.Add_Checked((Register-Handler { Update-MethodChip }))
$ui.ChkOverrideMethod.Add_Unchecked((Register-Handler { Update-MethodChip }))
$ui.CmbEnvironment.Add_SelectionChanged((Register-Handler { Update-ContextBanner }))
$ui.TxtRelativePath.Add_TextChanged((Register-Handler { Update-EffectiveRequest }))
$ui.TxtUri.Add_TextChanged((Register-Handler { Update-EffectiveRequest }))
$ui.CmbApiVersion.Add_SelectionChanged((Register-Handler { Update-EffectiveRequest }))
$ui.TxtOutputFile.Add_TextChanged((Register-Handler { Update-EffectiveRequest }))
$ui.TxtHeaders.Add_TextChanged((Register-Handler { Update-EffectiveRequest }))
$ui.TxtBody.Add_TextChanged((Register-Handler { Update-EffectiveRequest }))

$ui.BtnTheme.Add_Click((Register-Handler {
            $next = if ($script:App.Theme -eq 'Light') { 'Dark' } else { 'Light' }
            Set-GuiTheme -Name $next
        }))

$ui.BtnGuide.Add_Click((Register-Handler { Set-WelcomeVisible -Visible $true }))

$ui.BtnWelcomeClose.Add_Click((Register-Handler { Set-WelcomeVisible -Visible $false }))

$searchTimer = [System.Windows.Threading.DispatcherTimer]::new()
$searchTimer.Interval = [TimeSpan]::FromMilliseconds($script:SearchDebounceMs)
$searchTimer.Add_Tick((Register-Handler {
            # Stopped first: a slow rebuild must not queue another tick behind itself.
            $script:App.SearchTimer.Stop()
            if (-not $script:Window.IsLoaded) { return }
            $text = [string]$script:App.SearchPending
            if ($text -eq $script:App.SearchApplied) { return }
            $script:App.SearchApplied = $text
            Build-CatalogTree -Filter $text
        }))
$script:App.SearchTimer = $searchTimer

$ui.TxtSearch.Add_TextChanged((Register-Handler {
            if ($script:App.SearchSuppress) { return }
            $text = [string]$ui.TxtSearch.Text
            # Hint visibility is immediate; only the rebuild is debounced.
            $ui.TxtSearchHint.Visibility = if ([string]::IsNullOrEmpty($text)) { 'Visible' } else { 'Collapsed' }
            $script:App.SearchPending = $text
            $script:App.SearchTimer.Stop()      # Stop then Start restarts the 80 ms window
            $script:App.SearchTimer.Start()
        }))

$script:DeployedFilterToggled = Register-Handler {
    $wanted = ($ui.ChkDeployedOnly.IsChecked -eq $true)
    $script:App.DeployedOnly = $wanted

    if (-not $wanted -or $null -ne $script:App.DeployedTypes) {
        $shown = Update-CatalogView
        if ($wanted) { Set-Status ('Showing {0} operations for resource types you have deployed' -f $shown) }
        else { Set-Status ('Showing all {0} operations' -f $shown) }
        return
    }
    if ($null -eq $script:App.Context) { return }

    $subscriptionId = [string]$script:App.Context.SubscriptionId
    if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
        $ui.ChkDeployedOnly.IsChecked = $false
        Set-Status 'Select a subscription before filtering by what is deployed.' -Kind 'Problem'
        return
    }
    Invoke-Worker -Script 'param($SubId) Get-ArmGuiDeployedType -SubscriptionId $SubId' `
        -Parameters @{ SubId = $subscriptionId } -StatusText 'Reading deployed resource types' -OnSuccess {
        param($result)
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        # Stored lower-cased so a plain array would match identically.
        foreach ($armType in @($result)) { if ($armType) { $null = $set.Add(([string]$armType).ToLowerInvariant()) } }
        $script:App.DeployedTypes = $set
        $shown = Update-CatalogView
        Set-Status ('Showing {0} operations across {1} deployed resource types' -f $shown, $set.Count)
    } -OnFailure {
        param($message)
        $ui.ChkDeployedOnly.IsChecked = $false
        $script:App.DeployedOnly = $false
        Set-Status ('Could not read deployed resource types. ' + (ConvertTo-SafeErrorText $message)) -Kind 'Problem'
    }
}
$ui.ChkDeployedOnly.Add_Checked($script:DeployedFilterToggled)
$ui.ChkDeployedOnly.Add_Unchecked($script:DeployedFilterToggled)

$ui.TreeCatalog.Add_SelectedItemChanged((Register-Handler {
            $selected = $ui.TreeCatalog.SelectedItem

            # Re-assigning ItemsSource raises this with a null selection. Returning here
            # is what keeps the current operation alive across a filter change.
            if ($selected -isnot [ArmGui.CatalogNode]) { return }
            if ($selected.IsGroup -or $null -eq $selected.Payload) { return }

            if ($selected.Kind -eq 'Operation') {
                Select-DiscoveredOperation -Operation $selected.Payload
                return
            }
            $ui.RbPreset.IsChecked = $true
            Select-Preset -Preset $selected.Payload
        }))

# Walks a clicked visual up to its catalog row. Separate from the event handler so the
# targeting logic is testable: a synthesized routed event does not reach a TreeView
# handler outside a real message loop, but this function does.
function Get-CatalogRowFromVisual {
    param([AllowNull()][object]$Source)
    $element = $Source
    while ($null -ne $element -and $element -isnot [System.Windows.Controls.TreeViewItem]) {
        if ($element -is [System.Windows.Media.Visual] -or $element -is [System.Windows.Media.Media3D.Visual3D]) {
            $element = [System.Windows.Media.VisualTreeHelper]::GetParent($element)
        }
        else { $element = $null }
    }
    return $element
}

# WPF routes the right-click to the TreeView, not the row, so without this the menu
# would act on whatever was selected before rather than what the user clicked.
$ui.TreeCatalog.Add_PreviewMouseRightButtonDown((Register-Handler {
            param($treeSender, $mouseArgs)
            $row = Get-CatalogRowFromVisual -Source $mouseArgs.OriginalSource
            if ($null -ne $row) { $row.IsSelected = $true; $row.Focus() | Out-Null }
        }))

# The menu offers documentation only for a real operation, never for a group header.
$ui.MenuCatalog.Add_Opened((Register-Handler {
            $selected = $ui.TreeCatalog.SelectedItem
            $isOperation = ($selected -is [ArmGui.CatalogNode]) -and (-not $selected.IsGroup) -and ($null -ne $selected.Payload)
            $ui.MenuDocs.IsEnabled = $isOperation
            $ui.MenuCopyDocs.IsEnabled = $isOperation
            if ($isOperation) {
                $ui.MenuDocs.Header = 'View documentation for ' + [string](Get-SafeProperty -InputObject $selected.Payload -Name 'Name')
            }
            else { $ui.MenuDocs.Header = 'View documentation' }
        }))

$ui.MenuDocs.Add_Click((Register-Handler {
            $selected = $ui.TreeCatalog.SelectedItem
            if ($selected -isnot [ArmGui.CatalogNode] -or $selected.IsGroup -or $null -eq $selected.Payload) { return }
            Show-OperationDocs -Operation $selected.Payload
        }))

$ui.MenuCopyDocs.Add_Click((Register-Handler {
            $selected = $ui.TreeCatalog.SelectedItem
            if ($selected -isnot [ArmGui.CatalogNode] -or $selected.IsGroup -or $null -eq $selected.Payload) { return }
            $name = [string](Get-SafeProperty -InputObject $selected.Payload -Name 'Name')
            if ($script:DocsUrlCache.ContainsKey($name)) { $resolved = $script:DocsUrlCache[$name] }
            else {
                $candidates = @(Get-ArmDocsCandidate -Operation $selected.Payload)
                if ($candidates.Count -eq 0) { return }
                $resolved = Resolve-ArmDocsUrl -Candidate $candidates
                $script:DocsUrlCache[$name] = $resolved
            }
            Set-Clipboard -Value $resolved.Url
            Set-Status ('Documentation link copied for {0}' -f $name)
        }))

$modeChanged = Register-Handler {
    $mode = Get-RequestMode
    $ui.PanelPreset.Visibility = if ($mode -eq 'Preset') { 'Visible' } else { 'Collapsed' }
    $ui.PanelPath.Visibility = if ($mode -eq 'Path') { 'Visible' } else { 'Collapsed' }
    $ui.PanelUri.Visibility = if ($mode -eq 'Uri') { 'Visible' } else { 'Collapsed' }
    $ui.ChkOverrideMethod.IsEnabled = ($mode -eq 'Preset')
    $ui.ChkOverrideApiVersion.IsEnabled = ($mode -eq 'Preset')
    Update-MethodChip
}
$ui.RbPreset.Add_Checked($modeChanged)
$ui.RbPath.Add_Checked($modeChanged)
$ui.RbUri.Add_Checked($modeChanged)

$bodyChanged = Register-Handler {
    $ui.TxtBody.IsEnabled = ($ui.RbBodyInline.IsChecked -eq $true)
    $ui.GridBodyFile.Visibility = if ($ui.RbBodyFile.IsChecked -eq $true) { 'Visible' } else { 'Collapsed' }
    Update-EffectiveRequest
}
$ui.RbBodyNone.Add_Checked($bodyChanged)
$ui.RbBodyInline.Add_Checked($bodyChanged)
$ui.RbBodyFile.Add_Checked($bodyChanged)

$ui.BtnFormatJson.Add_Click((Register-Handler {
            $text = [string]$ui.TxtBody.Text
            if ([string]::IsNullOrWhiteSpace($text)) { return }
            $ui.TxtBody.Text = ($text | ConvertFrom-Json -ErrorAction Stop | ConvertTo-Json -Depth 100)
        }))

$ui.BtnUseExample.Add_Click((Register-Handler {
            $preset = $script:App.SelectedPreset
            if ($null -eq $preset -or [string]::IsNullOrWhiteSpace($preset.ExampleBody)) {
                Show-Message -Text 'This operation does not define an example body.' -Caption 'No example'
                return
            }
            $ui.RbBodyInline.IsChecked = $true
            $ui.TxtBody.Text = $preset.ExampleBody
        }))

$ui.BtnBrowseBody.Add_Click((Register-Handler {
            $dialog = New-Object Microsoft.Win32.OpenFileDialog
            $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
            $dialog.Title = 'Select a JSON request body'
            if ($dialog.ShowDialog($script:Window) -eq $true) { $ui.TxtBodyFile.Text = $dialog.FileName }
        }))

$ui.CmbScope.Add_SelectionChanged((Register-Handler { Select-DiscoveredScopeVariant; Update-EffectiveRequest }))

$ui.BtnDiscover.Add_Click((Register-Handler {
            if ($null -eq $script:App.Context) {
                Show-Message -Text 'Sign in before discovering operations.' -Caption 'Sign in required' -Icon 'Warning'
                return
            }
            $text = "Discovery queries every resource provider and operation available to this subscription.`r`n`r`n" +
            "It reads metadata only and changes nothing.`r`n`r`nThis can take up to a minute. Continue?"
            if (-not (Confirm-Action -Text $text -Caption 'Discover ARM operations')) { return }

            $ui.TxtCatalogStatus.Text = 'Discovering ARM operations...'
            Invoke-Worker -Script 'Get-ArmGuiOperationCatalog' -StatusText 'Discovering ARM operations' -OnSuccess {
                param($result)
                $payload = @($result)[-1]
                $operations = @(Get-SafeProperty -InputObject $payload -Name 'Operations')
                $script:App.CatalogInfo = $payload
                # Curated presets stay first so a verified entry always outranks a derived one.
                $curated = @($script:App.Catalog | Where-Object { $_.IsPreset -ne $false })
                $script:App.Catalog = @($curated) + @($operations)
                Initialize-CatalogSearchIndex -Catalog $script:App.Catalog
                Build-CatalogTree -Filter ([string]$ui.TxtSearch.Text)
                $ui.TxtCatalogStatus.Text = ('{0} verified presets and {1} discovered operations from {2} providers. Excluded {3} data-plane actions.' -f $curated.Count, $operations.Count, (Get-SafeProperty -InputObject $payload -Name 'ProviderCount'), (Get-SafeProperty -InputObject $payload -Name 'DataActions'))
                $ui.TxtIntegrity.Text = ('{0} operations available' -f $script:App.Catalog.Count)
                Set-Status ('Discovered {0} ARM operations' -f $operations.Count)
            } -OnFailure {
                param($message)
                $ui.TxtCatalogStatus.Text = 'Discovery failed. The verified presets remain available.'
                $safe = Get-FriendlyFailureText -Message $message
                if ($safe -match 'Authorization|403|Forbidden') {
                    $safe = "Discovered operations are unavailable because this account lacks Microsoft.Authorization/providerOperations/read.`r`n`r`nThe verified presets remain available.`r`n`r`n" + $safe
                }
                Show-Message -Text $safe -Caption 'Discovery failed' -Icon 'Warning'
            }
        }))

$ui.BtnDefaults.Add_Click((Register-Handler { Show-DefaultsDialog }))

$ui.BtnDefaultsApply.Add_Click((Register-Handler {
            Set-ParameterDefaults -Table (ConvertFrom-DefaultsText -Text ([string]$ui.TxtDefaults.Text))
            $applied = Use-ParameterDefaults
            Set-Status ('Applied {0} default value(s) to the current operation' -f $applied)
        }))

$ui.BtnDefaultsSave.Add_Click((Register-Handler {
            $table = ConvertFrom-DefaultsText -Text ([string]$ui.TxtDefaults.Text)
            $status = Save-DefaultsWithChoice -Table $table
            if ([string]::IsNullOrEmpty($status)) { return }
            Set-ParameterDefaults -Table $table
            $ui.TxtDefaultsPath.Text = $status
            Set-Status ('Saved {0} default value(s)' -f $table.Count)
        }))

$ui.BtnDefaultsSaveAs.Add_Click((Register-Handler {
            $table = ConvertFrom-DefaultsText -Text ([string]$ui.TxtDefaults.Text)
            $dialog = New-Object Microsoft.Win32.SaveFileDialog
            $dialog.Filter = 'Encrypted defaults (*.dat)|*.dat|Plain JSON, unencrypted (*.json)|*.json'
            $dialog.FileName = 'parameter-defaults.dat'
            $dialog.Title = 'Save parameter defaults'
            if ($dialog.ShowDialog($script:Window) -ne $true) { return }
            $plain = ($dialog.FilterIndex -eq 2)
            $warning = if ($plain) {
                "You chose PLAIN JSON, which is NOT encrypted.`r`n`r`nAnyone who can read the file, including backup, sync, and search indexing, can read every value in it.`r`n`r`nContinue?"
            }
            else {
                "The file is encrypted with your Windows account, so only you on this machine can read it.`r`n`r`nIt still contains values that identify your environment. Do not share it.`r`n`r`nContinue?"
            }
            if (-not (Confirm-Action -Text $warning -Caption 'Save parameter defaults')) { return }
            Set-ParameterDefaults -Table $table
            $saved = Save-ParameterDefaults -Path $dialog.FileName -Table $table -Plain:$plain
            $ui.TxtDefaultsPath.Text = if ($plain) { 'Saved UNENCRYPTED to ' + $saved } else { 'Saved and encrypted to ' + $saved }
            Set-Status ('Saved {0} default value(s)' -f $table.Count)
        }))

$ui.BtnDefaultsLoad.Add_Click((Register-Handler {
            $dialog = New-Object Microsoft.Win32.OpenFileDialog
            $dialog.Filter = 'Defaults (*.dat;*.json)|*.dat;*.json|All files (*.*)|*.*'
            $dialog.Title = 'Load parameter defaults'
            if ($dialog.ShowDialog($script:Window) -ne $true) { return }
            $table = Import-ParameterDefaults -Path $dialog.FileName
            if ($null -eq $table) { Set-Status 'That file is empty.'; return }
            Set-ParameterDefaults -Table $table
            $ui.TxtDefaultsPath.Text = 'Loaded from ' + $dialog.FileName
            Set-Status ('Loaded {0} default value(s)' -f $table.Count)
        }))

$ui.BtnDocs.Add_Click((Register-Handler {
            $operation = $ui.BtnDocs.Tag
            if ($null -eq $operation) { return }
            Show-OperationDocs -Operation $operation
        }))

# Everything here was resolved against the tenant being left, so none of it may be
# shown or reused under the new one.
function Clear-TenantScopedState {
    $script:App.Catalog = @($script:App.Catalog | Where-Object { $_.IsPreset -ne $false })
    $script:App.CatalogInfo = $null
    $script:App.SelectedDiscovered = $null
    # Deployed types belong to the subscription being left.
    $script:App.DeployedTypes = $null
    # A projection outlives the catalog entry behind it, so it goes too. A curated
    # preset is tenant-independent and stays.
    if ($null -ne $script:App.SelectedPreset -and
        (Get-SafeProperty -InputObject $script:App.SelectedPreset -Name 'IsDiscoveredProjection')) {
        $script:App.SelectedPreset = $null
    }

    # Tag holds memoized Azure lookups keyed to the old tenant's resource names.
    foreach ($key in @($script:App.ParamBoxes.Keys)) {
        $control = $script:App.ParamBoxes[$key]
        if ($null -eq $control) { continue }
        try { $control.Tag = $null; $control.Items.Clear() } catch { }
    }

    Initialize-CatalogSearchIndex -Catalog $script:App.Catalog
    Build-CatalogTree
    Clear-ResponseState
    Clear-DocsUrlCache
    $ui.TxtCatalogStatus.Text = ('{0} verified presets. Select Discover all to load every ARM operation.' -f @($script:App.Catalog).Count)
}

$ui.BtnTenant.Add_Click((Register-Handler {
            $app = $script:App
            $uiRef = $ui
            if ($null -eq $app.Context) { return }

            # The active context, never the dropdown: switching tenant must not
            # silently switch cloud because the user changed the combo after sign-in.
            $activeEnvironment = [string]$app.Context.Environment
            $currentTenantId = [string]$app.Context.TenantId

            Invoke-Worker -Script 'Get-ArmGuiTenant' -StatusText 'Listing tenants' -OnSuccess {
                param($result)
                $tenants = @(@($result) | Where-Object { $null -ne $_ -and $_.Id })
                if ($tenants.Count -eq 0) {
                    Show-Message -Text 'No tenants were returned for this account.' -Caption 'Switch tenant' -Icon 'Warning'
                    return
                }
                Set-TenantNameCache -Tenants $tenants

                $chosen = Show-TenantDialog -Tenants $tenants -CurrentTenantId $currentTenantId
                if ([string]::IsNullOrWhiteSpace($chosen) -or $chosen -eq $currentTenantId) { Set-Status 'Tenant unchanged'; return }

                $prompt = "Switch to tenant $chosen ?`r`n`r`nThis signs in again and may prompt in a browser. Discovered operations and the current response are discarded."
                if (-not (Confirm-Action -Text $prompt -Caption 'Switch tenant')) { Set-Status 'Tenant unchanged'; return }

                # Parameter names are deliberately distinct from the core script's own
                # param() variables, which are in scope in the worker runspace.
                $switchScript = 'param($SwitchEnvironment,$SwitchTenantId) Connect-ArmGui -Environment $SwitchEnvironment -TenantId $SwitchTenantId'
                Invoke-Worker -Script $switchScript `
                    -Parameters @{ SwitchEnvironment = $activeEnvironment; SwitchTenantId = $chosen } `
                    -StatusText ('Switching to tenant ' + $chosen) -OnSuccess {
                    param($switchResult)
                    $context = @($switchResult)[-1]
                    $app.Context = $context
                    Clear-TenantScopedState
                    Update-ContextBanner
                    Update-SubscriptionForSelectedPreset

                    $landed = if ($null -ne $context) { [string]$context.TenantId } else { '' }
                    if ($landed -ne $chosen) {
                        Show-Message -Text ("The session did not land on the tenant you chose.`r`n`r`nRequested: {0}`r`nActive: {1}" -f $chosen, $landed) -Caption 'Switch tenant' -Icon 'Warning'
                    }
                    elseif ([string]::IsNullOrWhiteSpace([string]$context.SubscriptionId)) {
                        Show-Message -Text 'Signed in to the tenant, but no subscription is active in it. Requests that need a subscription will fail until one is selected.' -Caption 'Switch tenant' -Icon 'Warning'
                    }
                    Set-Status ('Tenant ' + (Get-TenantLabel -TenantId $landed))
                    Start-DefaultsRevalidation
                }.GetNewClosure() -OnFailure {
                    param($message)
                    Show-Message -Text (Get-FriendlyFailureText -Message $message) -Caption 'Switch tenant failed' -Icon 'Error'
                    # A failed connect may already have torn down the old context, so ask
                    # the worker what is actually active rather than assuming it survived.
                    Invoke-Worker -Script 'Get-ArmGuiContext' -StatusText 'Rechecking sign-in' -OnSuccess {
                        param($recheck)
                        $app.Context = @($recheck)[-1]
                        Update-ContextBanner
                        if ($null -eq $app.Context) {
                            $uiRef.BtnDiscover.IsEnabled = $false
                            Set-Status 'Signed out by the failed switch. Sign in again to continue.' -Kind 'Problem'
                        }
                        else { Set-Status ('Still signed in to tenant ' + [string]$app.Context.TenantId) }
                    }.GetNewClosure()
                }.GetNewClosure()
            }.GetNewClosure() -OnFailure {
                param($message)
                Show-Message -Text (Get-FriendlyFailureText -Message $message) -Caption 'Could not list tenants' -Icon 'Error'
            }
        }))

$ui.BtnDefaultsClear.Add_Click((Register-Handler {
            $path = Get-DefaultsPath
            $hasFile = Test-Path -LiteralPath $path -PathType Leaf
            $text = if ($hasFile) { "Clear the editor and delete the saved file at`r`n`r`n$path`r`n`r`nContinue?" }
            else { 'Clear all parameter defaults?' }
            if (-not (Confirm-Action -Text $text -Caption 'Clear parameter defaults')) { return }
            Set-ParameterDefaults -Table ([ordered]@{})
            if ($hasFile) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
            $ui.TxtDefaultsPath.Text = 'No saved defaults.'
            Set-Status 'Parameter defaults cleared'
        }))

$ui.BtnClearLog.Add_Click((Register-Handler {
            $script:App.LogLines.Clear()
            $script:App.PendingLog.Length = 0
            $ui.TxtLog.Clear()
        }))

$ui.BtnCopyCli.Add_Click((Register-Handler {
            $request = Build-RequestArguments
            [System.Windows.Clipboard]::SetText((Get-CliPreview -Request $request))
            Set-Status 'Equivalent command line copied to the clipboard'
        }))

$ui.BtnCancel.Add_Click((Register-Handler { Stop-Worker }))

$ui.BtnReveal.Add_Click((Register-Handler {
            if ($script:App.Revealed) { Hide-Reveal; return }
            $text = "The raw response may contain live credentials or sensitive data.`r`n`r`n" +
            "It will be shown for $script:RevealSeconds seconds and then hidden automatically.`r`n`r`n" +
            'Confirm no one else can see this screen. Continue?'
            if (-not (Confirm-Action -Text $text -Caption 'Reveal raw response')) { return }
            $script:App.Revealed = $true
            Set-ResponseText -Text $script:App.RawResponse
            Set-RevealLock -Locked $true
            $ui.BtnReveal.Content = 'Hide raw'
            $script:App.RevealTimer.Start()
            Set-Status ('Raw response visible for {0} seconds' -f $script:RevealSeconds)
        }))

$ui.BtnCopyResponse.Add_Click((Register-Handler {
            if ([string]::IsNullOrEmpty($script:App.RedactedText)) { return }
            [System.Windows.Clipboard]::SetText($script:App.RedactedText)
            Set-Status 'Redacted response copied to the clipboard'
        }))

$ui.BtnSaveResponse.Add_Click((Register-Handler {
            if ([string]::IsNullOrEmpty($script:App.RedactedText)) { return }
            $dialog = New-Object Microsoft.Win32.SaveFileDialog
            $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
            $dialog.FileName = 'arm-response.json'
            $dialog.Title = 'Save redacted response'
            if ($dialog.ShowDialog($script:Window) -eq $true) {
                # StreamWriter rather than Set-Content: 5.1 writes a UTF-8 BOM and 7.x does not.
                $writer = [IO.StreamWriter]::new($dialog.FileName, $false, [Text.UTF8Encoding]::new($false))
                try { $writer.Write($script:App.RedactedText) } finally { $writer.Dispose() }
                Set-Status ('Redacted response saved to {0}' -f $dialog.FileName)
            }
        }))

$ui.BtnSignIn.Add_Click((Register-Handler {
            $environment = [string]$ui.CmbEnvironment.SelectedItem
            $useDeviceCode = $false
            if ($environment -ne 'AzureCloud') {
                $prompt = "You are signing in to $environment.`r`n`r`nConfirm this is the correct cloud for the environment you intend to work in."
                if (-not (Confirm-Action -Text $prompt -Caption 'Confirm cloud')) { return }
            }
            $workerScript = 'param($Environment,$UseDeviceCode) Initialize-ArmRuntime -Environment $Environment | Out-Null; Connect-ArmGui -Environment $Environment -UseDeviceCode $UseDeviceCode'
            Invoke-Worker -Script $workerScript -Parameters @{ Environment = $environment; UseDeviceCode = $useDeviceCode } -StatusText 'Signing in' -OnSuccess {
                param($result)
                $context = @($result)[-1]
                $script:App.Context = $context
                Update-ContextBanner
                $ui.BtnDiscover.IsEnabled = $true
                $ui.ChkDeployedOnly.IsEnabled = $true
                $ui.TxtCatalogStatus.Text = ('{0} verified presets. Select Discover all to load every ARM operation.' -f @($script:App.Catalog | Where-Object { $_.IsPreset -ne $false }).Count)
                Set-Status 'Signed in'
                Update-SubscriptionForSelectedPreset
                Start-TenantNameLookup
            } -OnFailure {
                param($message)
                Show-Message -Text (Get-FriendlyFailureText -Message $message) -Caption 'Sign-in failed' -Icon 'Error'
            }
        }))

$ui.BtnSignOut.Add_Click((Register-Handler {
            Invoke-Worker -Script 'Disconnect-ArmGui' -StatusText 'Signing out' -OnSuccess {
                param($result)
                $script:App.Context = $null
                $script:App.TenantNames = @{}
                # Discovered operations are subscription-specific, so they must not
                # outlive the context that produced them.
                $script:App.Catalog = @($script:App.Catalog | Where-Object { $_.IsPreset -ne $false })
                $script:App.CatalogInfo = $null
                $script:App.SelectedDiscovered = $null
                Initialize-CatalogSearchIndex -Catalog $script:App.Catalog
                Build-CatalogTree
                $ui.BtnDiscover.IsEnabled = $false
                $ui.ChkDeployedOnly.IsEnabled = $false
                $ui.ChkDeployedOnly.IsChecked = $false
                $script:App.DeployedTypes = $null
                $ui.TxtCatalogStatus.Text = 'Verified presets only. Sign in to discover every ARM operation.'
                Clear-ResponseState
                Clear-DocsUrlCache
                Update-ContextBanner
                Set-Status 'Signed out'
            }
        }))

$ui.BtnSelfTest.Add_Click((Register-Handler {
            Invoke-Worker -Script 'Initialize-ArmRuntime | Out-Null; Invoke-ArmGuiSelfTest' -StatusText 'Running self-test' -OnSuccess {
                param($result)
                $ui.TabResponse.SelectedIndex = 0
                $text = (@($result) -join [Environment]::NewLine)
                Show-Response -Raw $text -Redacted $text -Target 'selftest'
                Set-Status 'Self-test complete'
            }
        }))

$ui.BtnSend.Add_Click((Register-Handler {
            $request = Build-RequestArguments
            if (-not (Confirm-Request -Request $request)) { Set-Status 'Request cancelled' -Kind 'Problem'; return }

            $ui.BorderStatusChip.Visibility = 'Collapsed'
            $ui.TxtCorrelation.Text = ''
            Clear-ResponseState
            $ui.TabResponse.SelectedIndex = 2

            $summary = Get-RequestSummary -Request $request
            $script:App.LastSummary = $summary
            $environment = [string]$ui.CmbEnvironment.SelectedItem
            $debug = ($ui.ChkDebugLogging.IsChecked -eq $true)
            $enforce = ($ui.ChkEnforceSignature.IsChecked -eq $true)
            $bundled = ($ui.ChkPreferBundled.IsChecked -eq $true)

            $workerScript = @'
param($Request, $Environment, $DebugLogging, $EnforceSignature, $PreferBundled)
Initialize-ArmRuntime -Environment $Environment -DebugLogging $DebugLogging -EnforceSignature $EnforceSignature -PreferBundled $PreferBundled | Out-Null
Invoke-ArmGuiRequest @Request
'@
            $parameters = @{
                Request          = $request
                Environment      = $environment
                DebugLogging     = $debug
                EnforceSignature = $enforce
                PreferBundled    = $bundled
            }
            Invoke-Worker -Script $workerScript -Parameters $parameters -StatusText ('{0} {1}' -f $summary.Method, $summary.Target) -OnSuccess {
                param($result)
                $payload = @($result)[-1]
                $raw = [string](Get-SafeProperty -InputObject $payload -Name 'Raw')
                $redacted = [string](Get-SafeProperty -InputObject $payload -Name 'Redacted')
                $ui.TabResponse.SelectedIndex = 0
                Show-Response -Raw $raw -Redacted $redacted -Target ([string]$script:App.LastSummary.SecretProbe)
                $savePath = [string](Get-SafeProperty -InputObject $payload -Name 'SavePath')
                $saveError = [string](Get-SafeProperty -InputObject $payload -Name 'SaveError')
                if ($saveError) { Add-LogLine ('WARN Could not save the response: ' + $saveError) }
                elseif ($savePath) { Add-LogLine ('Redacted response saved to ' + $savePath) }
                $ui.BorderStatusChip.Visibility = 'Visible'
                $ui.TxtStatusChip.Text = 'Succeeded'
                $ui.BorderStatusChip.Background = $script:Window.FindResource('State.Success')
                Set-Status 'Request completed'
            } -OnFailure {
                param($message)
                $ui.TabResponse.SelectedIndex = 2
                $ui.BorderStatusChip.Visibility = 'Visible'
                $ui.TxtStatusChip.Text = 'Failed'
                $ui.BorderStatusChip.Background = $script:Window.FindResource('State.Danger')
                Show-Message -Text (Get-FriendlyFailureText -Message $message) -Caption 'Request failed' -Icon 'Error'
            }
        }))

function Update-SubscriptionForSelectedPreset {
    $context = $script:App.Context
    if ($null -eq $context) { return }
    $box = $script:App.ParamBoxes['subscriptionId']
    if ($null -ne $box -and $box -is [System.Windows.Controls.TextBox] -and [string]::IsNullOrWhiteSpace($box.Text)) {
        $box.Text = [string]$context.SubscriptionId
    }
}

# ==============================================================================
# REGION 17  Lifecycle
# ==============================================================================

$revealTimer = [System.Windows.Threading.DispatcherTimer]::new()
$revealTimer.Interval = [TimeSpan]::FromSeconds($script:RevealSeconds)
$revealTimer.Add_Tick((Register-Handler { Hide-Reveal }))
$script:App.RevealTimer = $revealTimer

$script:Window.Add_Deactivated((Register-Handler { Hide-Reveal }))

$script:Window.Add_Closing((Register-Handler {
            param($eventSender, $eventArgs)
            if ($script:App.Busy) {
                if (-not (Confirm-Action -Text 'An operation is still running. Cancel it and close?' -Caption 'Close')) {
                    $eventArgs.Cancel = $true
                    return
                }
                Stop-Worker
            }
        }))

$script:Window.Add_Closed((Register-Handler {
            if ($null -ne $script:App.Pump) { $script:App.Pump.Stop() }
            if ($null -ne $script:App.RevealTimer) { $script:App.RevealTimer.Stop() }
            # The dispatcher, not the window, roots a DispatcherTimer; Close does not stop it.
            if ($null -ne $script:App.SearchTimer) { $script:App.SearchTimer.Stop() }
            if ($null -ne $script:App.Worker) { try { $script:App.Worker.Dispose() } catch { } }
            if ($null -ne $script:App.Runspace) { try { $script:App.Runspace.Close(); $script:App.Runspace.Dispose() } catch { } }
        }))

$script:Window.Add_Loaded((Register-Handler {
            # Never open larger than the monitor work area, otherwise the title bar
            # lands off-screen on a 1366x768 display and the window cannot be moved.
            $work = [System.Windows.SystemParameters]::WorkArea
            $script:Window.Width = [Math]::Min($script:Window.Width, $work.Width)
            $script:Window.Height = [Math]::Min($script:Window.Height, $work.Height)
            $script:Window.Left = $work.X + [Math]::Max(0, ($work.Width - $script:Window.Width) / 2)
            $script:Window.Top = $work.Y + [Math]::Max(0, ($work.Height - $script:Window.Height) / 2)

            Set-Status 'Loading ArmClient-PS'
            try { Start-Worker }
            catch {
                Show-Message -Text (ConvertTo-SafeErrorText $_.Exception.Message) -Caption 'Startup failed' -Icon 'Error'
                $script:Window.Close()
                return
            }

            $ps = [PowerShell]::Create()
            $ps.Runspace = $script:App.Runspace
            $null = $ps.AddScript('[pscustomobject]@{ Version = $Configuration.Version; Catalog = @(Get-ArmGuiCatalog) }')
            $info = $ps.Invoke()
            $ps.Dispose()

            $payload = @($info)[-1]
            $script:App.Version = [string](Get-SafeProperty -InputObject $payload -Name 'Version')
            $core = @(Get-SafeProperty -InputObject $payload -Name 'Catalog')
            $script:App.Catalog = @($core) + @(Get-ArmGuiExtendedPresetCatalog)
            Initialize-CatalogSearchIndex -Catalog $script:App.Catalog

            $ui.TxtVersion.Text = 'Azure Resource Manager console  ' + $script:App.Version
            $ui.TxtIntegrity.Text = ('{0} operations loaded' -f $script:App.Catalog.Count)

            $defaultsPath = Get-DefaultsPath
            try {
                $saved = Import-ParameterDefaults -Path $defaultsPath
                if ($null -ne $saved) {
                    Set-ParameterDefaults -Table $saved
                    $ui.TxtDefaultsPath.Text = 'Loaded from ' + $defaultsPath
                }
                else { $ui.TxtDefaultsPath.Text = 'No saved defaults. Values are saved encrypted to ' + $defaultsPath }
            }
            catch {
                $ui.TxtDefaultsPath.Text = 'Saved defaults could not be read. ' + $_.Exception.Message
            }
            Build-CatalogTree
            Update-ContextBanner
            Set-Status 'Ready. Select an operation, then sign in.'
        }))

Initialize-Pump
Initialize-StatusFade
Set-GuiTheme -Name $initialTheme
Initialize-Branding
& $modeChanged
& $bodyChanged
Update-MethodChip

$null = $script:Window.ShowDialog()

