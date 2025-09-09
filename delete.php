<?php
 
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}
 
require_once 'conn.php';
 
try {
    if (isset($_GET['id'])) {
        $id = $_GET['id'];
 
        $sql = "DELETE FROM crud_php WHERE id = ?";
        $stmt = $conn->prepare($sql);
 
        if ($stmt) {
            $stmt->bind_param("i", $id);
            if ($stmt->execute()) {
                session_start();
                $_SESSION['message'] = "Tarefa excluída com sucesso!";
                $_SESSION['message_type'] = "danger";
                header("Location: index.php");
                exit();
            } else {
                session_start();
                $_SESSION['message'] = "Erro ao excluir a tarefa.";
                $_SESSION['message_type'] = "danger";
                throw new Exception("Erro ao executar a exclusão: " . $stmt->error);
            }
 
            $stmt->close();
        } else {
            throw new Exception("Erro ao preparar a consulta: " . $conn->error);
        }
    } else {
        throw new Exception("ID da tarefa não fornecido.");
    }
} catch (Exception $e) {
    echo "Erro: " . $e->getMessage();
} finally {
    $conn->close();
}