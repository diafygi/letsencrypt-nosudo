<?php

if (!empty($_GET))
{
	if (isset($_GET['key1']) && isset($_GET['key1']) )
	{
		$key1 = $_GET['key1'];
		$key2 = $_GET['key2'];
		$path = ".well-known2/acme-challenge/";

		if (!is_dir($path))
		    mkdir($path, 0755, true);

		$keyfile = fopen($path . $key1, "w") or die("Unable to create file!");
		fwrite($keyfile, $key2);
		fclose($keyfile);

	}
}


?>
