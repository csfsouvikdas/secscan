<?php
// INTENTIONALLY VULNERABLE demo (SecScan). Never deploy this.
$conn = mysqli_connect("localhost", "root", "root_pass123", "shop");
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM orders WHERE id = " . $id);
echo "Hello " . $_GET['name'];
include($_GET['page']);
system("convert " . $_POST['file'] . " out.png");
$data = unserialize($_COOKIE['prefs']);
$hash = md5($_POST['password']);
