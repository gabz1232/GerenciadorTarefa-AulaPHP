<?php
 
session_start();
 
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}
 
require_once 'conn.php';
 
$id = isset($_GET['id']) ? $_GET['id'] : null;
 
if(!$id) {
    echo "ID da tarefa não fornecido";
    $_SESSION['message'] = "ID da tarefa não fornecido.";
    $_SESSION['message_type'] = "danger";
    header("Location: index.php");
    exit();
}
 
try {
    $sql = "SELECT * FROM crud_php WHERE id = ?";
    $stmt = $conn->prepare($sql);
 
    if($stmt){
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $result = $stmt->get_result();
 
        if($result->num_rows == 1) {
            $tasks = $result->fetch_assoc();
        } else {
            echo "Tarefa não encontrada!";
            exit();
        }
        $stmt->close();
    } else {
        $_SESSION['message'] = "ID da tarefa não fornecido.";
        $_SESSION['message_type'] = "danger";
        header("Location: index.php");
        throw new Exception("Erro ao preparar a consulta: " . $conn->error);
    }
} catch (Exception $e) {
    echo "Erro " . $e->getMessage();
    exit();
}
 
?>
 
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Editar Tarefa</title>
    <!-- BOOTSTRAP -->
    <link rel="stylesheet" href="https://bootswatch.com/4/yeti/bootstrap.min.css">
<!-- FONT AWESOME -->
 <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.6.3/css/all.css"
 integrity="sha384-UHRtZLI+pbxtHCWp1t77Bi1L4ZtiqrqD80Kn4Z8NTSRyMA2Fd33n5dQ8lWUE00s/" crossorigin="anonymous">
</head>
<body>
    <div class="container">
        <nav class="navbar navbar-light bg-light">
            <div class="container">
                <a class="navbar-brand" href="index.php">Crud PHP</a>
                <form action="" method="POST" class="d-inline">
                    <button type="submit" class="btn btn-secondary">
                        <i class="fas fa-sign-out-alt"></i>Logout
                    </button>
                </form>
            </div>
        </nav>
 
        <div class="container p-4">
            <div class="row">
                <div class="col-md-6 mx-auto">
                    <div class="card card-body">
                        <form action="update.php" method="POST">
                            <input type="hidden" name="id" value="<?php echo $tasks['id']; ?>">
                            <div class="form-group">
                                <input type="text" name="title" class="form-control" value="<?php echo $tasks['title']; ?>">
                                </div>
                                <div class="form-group">
                                    <textarea name="description" rows="2" class="form-control"><?php echo $tasks['description']; ?></textarea>
                                </div>
                                <button class="btn btn-success btn-block" type="submit">Atualizar</button>
                                <a href="index.php" class="btn btn-secondary btn-block">Cancelar</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
 
     <!-- BOOTSTRAP 4 SCRIPTS -->
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.6/umd/popper.min.js" integrity="sha384-wHAiFfRlMFy6i5SRaxvfOCifBUQy1xHdJ/yoi7FRNXMRBu5WHdZYu1hA6ZOblgut" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.2.1/js/bootstrap.min.js" integrity="sha384-B0UglyR+jN6CkvvICOB2joaf5I4l3gm9GU6Hc1og6Ls7i6U/mkkaduKaBhlAXv9k" crossorigin="anonymous"></script>
   
</body>
</html>