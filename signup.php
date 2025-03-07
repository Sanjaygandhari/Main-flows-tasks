
<?php
include "config.php";

if (isset($_POST["signup"])) {
    $username = $_POST["username"];
    $email = $_POST["email"];
    $password = $_POST["password"];
    $confirm_password = $_POST["confirm_password"];

    if ($password !== $confirm_password) {
        die("Passwords do not match!");
    }

    $query = $conn->prepare("SELECT * FROM users WHERE email = ? OR username = ?");
    $query->bind_param("ss", $email, $username);
    $query->execute();
    $result = $query->get_result();

    if ($result->num_rows > 0) {
        die("Username or email already exists!");
    }

    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $email, $hashed_password);
    
    if ($stmt->execute()) {
        echo "Signup successful! <a href='login.html'>Login</a>";
    } else {
        echo "Error: " . $stmt->error;
    }
}
?>
