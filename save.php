<?php

session_start();
if(!isset($_SESSION['user_id'])){
    header("Location: login.php");
    exit();
}

require_once 'conn.php';

try {
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $title = isset($_POST['title']) ? $_POST['title'] : null;
        $description = isset($_POST['description']) ? $_POST['description'] : null;


        if ($title) {
            $sql = "INSERT INTO crud_php (title, description) VALUES (?,?)";
            $stmt = $conn->prepare($sql);

            if ($stmt) {
                $stmt->bind_param("ss", $title, $description);

                if ($stmt->execute()) {
                    session_start();
                    $_SESSION['message'] = "Tarefa salva com sucesso!";
                    $_SESSION['message_type'] = "success";
                    header("Location: index.php");
                    exit();
                } else {
                    session_start();
                    $_SESSION['message'] = "Erro ao salvar a tarefa.";
                    $_SESSION['message_type'] = "danger";
                    throw new Exception("Erro ao executar a consulta: " . $stmt->error);
                }
                $stmt->close();
            } else {
                throw new Exception("Erro ao preparar a consulta:" . $conn->error);
            }
        } else {
            throw new Exception("O campo title é obrigatório!");
        }
    } else {
        throw new Exception("Método de requisição inválido");
    }
} catch (Exception $e) {
    echo "Erro: " . $e->getMessage();
} finally {
    $conn->close();
}
