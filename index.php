<!DOCTYPE html>
<html lang="pt-br">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP CRUD MYSQL</title>
    <!--BOOSTRAP 4 -->
    <link rel="stylesheet" href="https://bootswatch.com/4/yeti/bootstrap.min.css">
    <!-- FONT AWESOME    -->
    <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.6.3/css/all.css"
        integrity="sha384-UHRtZLI+pbxtHCWp1t77Bi1L4ZtiqrqD80Kn4Z8NTSRyMA2Fd33n5dQ8lWUE00s/"
        crossorigin="anonymous">
</head>

<body>
    <div class="container">
        <nav class="navbar navbar-light bg-light">
            <div class="container">
                <a class="navbar-brand" href="index.php">Crud PHP </a>
            </div>
        </nav>
        <main class="container p-4">
            <div class="row">
                <div class="col-md-4">
                    <!-- Formulário -->
                    <div class="card card-body">
                        <form action="save.php" method="POST">
                            <div class="form-group">
                                <input type="text" name="title" class="form-control"
                                    placeholder="Task Title" autofocus>
                            </div>
                            <div class="form-group">
                                <textarea name="description" rows="2" class="form-control" placeholder="descricao da tarefa"></textarea>
                            </div>
                            <input type="submit" name="salvar" class="btn btn-success btn-block"
                                value="Save Task">
                        </form>
                    </div>
                </div>
                <!-- /Formulário -->

                <!-- Tabela de Tarefas -->
                <div class="col md-8">
                    <table class="table table-bordered">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Titulo</th>
                                <th>Descrição</th>
                                <th>Criado em</th>
                                <th>Ação</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            require_once 'conn.php';

                            $query = "SELECT id, title, description, created_at
                            FROM crud_php";
                            $result = $conn->query($query);

                            if ($result->num_rows > 0) {
                                while ($row = $result->fetch_assoc()) {
                            ?>


                                    <tr>
                                        <td><?php echo $row['id']; ?></td>
                                        <td><?php echo $row['title']; ?></td>
                                        <td><?php echo $row['description']; ?></td>
                                        <td><?=date("d/m/Y", strtotime( $row['created_at'])); ?></td>
                                        <td><a href="edit.php?id=<?= $row['id']; ?>" class="btn btn-secondary">
                                                <i class="fas fa-marker"></i>
                                            </a>
                                            <a href="delete.php?id=<?= $row['id']; ?> " class="btn btn-danger">
                                                <i class="far fa-trash-alt"></i>
                                            </a>
                                        </td>
                                    </tr>
                            <?php
                                }
                            } else {
                                echo "<tr><td colspan= '5'>Nenhuma tarefa encontrada!</td></tr>";
                            }
                            $conn->close();
                            ?>
                        </tbody>
                    </table>
                </div>
                <!-- /Tabela de Tarefas -->
            </div>
        </main>
    </div>

    <!-- BOOTSTRAP 4 SCRIPTS -->
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.6/umd/popper.min.js" integrity="sha384-wHAiFfRlMFy6i5SRaxvfOCifBUQy1xHdJ/yoi7FRNXMRBu5WHdZYu1hA6ZOblgut" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.2.1/js/bootstrap.min.js" integrity="sha384-B0UglyR+jN6CkvvICOB2joaf5I4l3gm9GU6Hc1og6Ls7i6U/mkkaduKaBhlAXv9k" crossorigin="anonymous"></script>
</body>

</html>