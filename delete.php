<?php

require_once 'conn.php';

try {
    if(isset($_GET['id'])){
        $id = $_GET['id'];

        $sql = "DELETE FROM crud_php WHERE id = ?";
        $stmt = $conn->prepare($sql);

        if ($stmt) {
            $stmt->bind_param("i", $id);
            if($stmt->execute()) {
                header("Location: index.php");
                exit();
            } else {
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