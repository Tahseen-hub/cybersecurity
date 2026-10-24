<?php
// SQL Injection Fix — Parameterized / Prepared Statement
// This replaces the vulnerable DVWA SQL Injection query shown at Low and Medium security levels.

$id = $_GET['id'];

// The '?' is a placeholder — it is bound as DATA, never concatenated into the SQL string.
// This means no matter what characters the input contains, it can never be interpreted
// as executable SQL syntax — eliminating the vulnerability entirely.
$stmt = $mysqli->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("s", $id);
$stmt->execute();

$result = $stmt->get_result();

while ($row = $result->fetch_assoc()) {
    echo '<pre>';
    echo 'ID: ' . htmlspecialchars($id) . '<br>First name: ' . htmlspecialchars($row['first_name']) .
         '<br>Surname: ' . htmlspecialchars($row['last_name']);
    echo '</pre>';
}

$stmt->close();

// Tested against both previously successful payloads:
//   1' OR '1'='1
//   1 UNION SELECT user, password FROM users-- -
// Both are treated as literal search values, not SQL — no extra rows returned, no errors.
?>