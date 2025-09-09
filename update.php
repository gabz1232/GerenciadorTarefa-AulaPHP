<?php

session_start();

if(!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

require_once 'conn.php';

try {
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $id = isset($_POST['id']) ? $_POST['id'] : null;
        $title = isset($_POST['title']) ? $_POST['title'] : null;
        $description = isset($_POST['description']) ? $_POST['description'] : null;

        if ($id && $title !== null) {
            $sql = "UPDATE crud_php SET title = ?, description = ? WHERE id = ?";
            $stmt = $conn->prepare($sql);

            if ($stmt) {
                $stmt->bind_param("ssi", $title, $description, $id);

                if ($stmt->execute()) {
                    $_SESSION['message'] = "Tarefa atualizada com sucesso!";
                    $_SESSION['message_type'] = 'primary';
                    header("Location: index.php");
                    exit();
                } else {
                     $_SESSION['message'] = "Erro ao atualizar a tarefa.";
                    $_SESSION['message_type'] = 'danger';
                    throw new Exception("Erro ao executar a atualização: " . $stmt->error);
                }
                $stmt->close();
            } else {
                throw new Exception("Erro ao preparar a consulta: " . $conn->error);
            }
        } else {
            throw new Exception("O campo 'Titulo' é obrigatório!");
        }
    } else {
        throw new Exception("Método de requisição inválido");
    }
} catch (Exception $e) {
    $_SESSION['message'] = "Erro: " . $e->getMessage();
    $_SESSION['message_type'] = "danger";
    header("Location: index.php");
    exit();
} finally {
    $conn->close();
}
