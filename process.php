<?php

//SSRF Vulnerability
$ip = $_POST['ip'];
$content = file_get_contents($ip);

//RCE Vulnerability
$org = $_POST['organization'];
$org_output=system($org);

//Response Output
echo $org_output, $content;
?>