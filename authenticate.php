<?php

require_once 'conn.php';

try {
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $email = isset($_POST['email']) ? $_POST['email'] : null;
        $password = isset($_POST['password']) ? $_POST['password'] : null; 

        if ($email && $password) {
        $sql = "SELECT id, email, password FROM users WHERE email = ?";
        $stmt = $conn->prepare($sql);  
                                                  
        if ($stmt) {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows == 1) {
                $user = $result->fetch_assoc();
                if (password_verify($password, $user['password'])) {
                    session_start();
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['email'] = $user['email'];
                    $_SESSION['message'] = "Bem-vindo!" . $user['email'];
                    $_SESSION['message_type'] = "primary";
                    header("Location: index.php");
                    exit();         
                } else {
                    throw new Exception(" Email ou senha invalidos!");
                }       
            } else {
                throw new Exception(" Email ou senha invalidos!"); 
        }
        $stmt ->close();
    } else {
        throw new Exception("Erro na preparação a consulta: " . $conn->error);
    }
} else {
        throw new Exception("Email e senha são obrigatórios.");
    }
} else {
    throw new Exception("Método de requisição inválido.");
}
} catch (Exception $e) {
    echo "Erro: " . $e->getMessage();

} finally {
    $conn->close();
}
