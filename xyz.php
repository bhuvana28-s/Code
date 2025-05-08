<?php
// Zeniq - Single PHP file full app example
// To run: Place this file in your PHP environment (e.g., XAMPP htdocs)
// Create MySQL database and tables using the schema below before running
/*
CREATE DATABASE zeniq;
USE zeniq;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    bio TEXT,
    interests TEXT,
    rewards INT DEFAULT 0
);
CREATE TABLE bank_accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    bank_name VARCHAR(100),
    account_number VARCHAR(50),
    ifsc VARCHAR(20),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE companies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    description TEXT,
    industry VARCHAR(50),
    location VARCHAR(100),
    website VARCHAR(100)
);
CREATE TABLE tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(150),
    description TEXT,
    assigned_to INT DEFAULT NULL,
    status ENUM('open', 'assigned', 'completed') DEFAULT 'open',
    reward_points INT DEFAULT 0
);
CREATE TABLE payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    amount DECIMAL(10,2),
    payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    reward_points_earned INT
);
-- Seed some companies manually or use below code section within this file (via ?action=seed_companies)
*/

session_start();

// Database connection settings
$dbHost = 'localhost';
$dbName = 'zeniq';
$dbUser = 'root';  // Change if necessary
$dbPass = '';      // Change if necessary

try {
    $pdo = new PDO("mysql:host=$dbHost;dbname=$dbName;charset=utf8mb4", $dbUser, $dbPass,
                   [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Helpers
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function getUser() {
    global $pdo;
    if (!isLoggedIn()) return null;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function h($str) {
    return htmlspecialchars($str);
}

function redirect($url) {
    header("Location: $url");
    exit;
}

// Actions for routing
$action = $_GET['action'] ?? 'home';

// Handle logout
if ($action === 'logout') {
    session_destroy();
    redirect('zeniq.php');
}

// Handle user registration
if ($action === 'register') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $errors = [];

        if (!$username || !$email || !$password) {
            $errors[] = 'All fields are required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid email format.';
        } else {
            // Check user or email exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
            $stmt->execute([$username, $email]);
            if ($stmt->fetch()) {
                $errors[] = 'Username or Email already exists.';
            }
        }

        if (empty($errors)) {
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt->execute([$username, $email, $passwordHash]);
            echo "<p class='success'>Registration successful! <a href='zeniq.php?action=login'>Login here</a></p>";
            $action = 'login'; // Show login form after register
        } else {
            foreach ($errors as $err) {
                echo "<p class='error'>" . h($err) . "</p>";
            }
        }
    }
    if ($action === 'register') {
        renderRegisterForm();
        exit;
    }
}

// Handle user login
if ($action === 'login') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $errors = [];

        if (!$username || !$password) {
            $errors[] = 'All fields are required.';
        } else {
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($user && password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                redirect('zeniq.php');
            } else {
                $errors[] = 'Invalid username or password.';
            }
        }

        if (!empty($errors)) {
            foreach ($errors as $err) {
                echo "<p class='error'>" . h($err) . "</p>";
            }
        }
    }
    renderLoginForm();
    exit;
}

// Handle company seeding (for demo)
if ($action === 'seed_companies') {
    seedCompanies($pdo);
    echo "<p class='success'>Companies seeded! <a href='zeniq.php?action=companies'>View Companies</a></p>";
    exit;
}

// Ensure logged in for below actions
if (!isLoggedIn() && in_array($action, ['profile', 'tasks', 'payments', 'companies', 'link_bank_account', 'ai'])) {
    redirect('zeniq.php?action=login');
}

// Process profile update
if ($action === 'profile') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $full_name = trim($_POST['full_name'] ?? '');
        $bio = trim($_POST['bio'] ?? '');
        $interests = trim($_POST['interests'] ?? '');

        $stmt = $pdo->prepare("UPDATE users SET full_name = ?, bio = ?, interests = ? WHERE id = ?");
        $stmt->execute([$full_name, $bio, $interests, $_SESSION['user_id']]);
        echo "<p class='success'>Profile updated!</p>";
    }
    renderProfile($pdo);
    exit;
}

// Process bank account linking
if ($action === 'link_bank_account' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $bank_name = trim($_POST['bank_name'] ?? '');
    $account_number = trim($_POST['account_number'] ?? '');
    $ifsc = trim($_POST['ifsc'] ?? '');
    $errors = [];

    if (!$bank_name || !$account_number || !$ifsc) {
        $errors[] = "All bank account fields are required.";
    }

    if (empty($errors)) {
        $stmt = $pdo->prepare("INSERT INTO bank_accounts (user_id, bank_name, account_number, ifsc) VALUES (?, ?, ?, ?)");
        $stmt->execute([$_SESSION['user_id'], $bank_name, $account_number, $ifsc]);
        echo "<p class='success'>Bank account linked!</p>";
    } else {
        foreach ($errors as $err) {
            echo "<p class='error'>" . h($err) . "</p>";
        }
    }
    renderProfile($pdo);
    exit;
}

// Show companies
if ($action === 'companies') {
    renderCompanies($pdo);
    exit;
}

// Show tasks page (dummy)
if ($action === 'tasks') {
    renderTasks($pdo);
    exit;
}

// Payments and rewards (dummy)
if ($action === 'payments') {
    renderPayments($pdo);
    exit;
}

// AI assistant - suggest users with similar interests
if ($action === 'ai') {
    renderAI($pdo);
    exit;
}

// Default home page
renderHome();


// Function definitions for rendering HTML pages and components

function renderHome() {
    ?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Zeniq - Home</title>
    <style><?php echo cssStyle(); ?></style>
</head>
<body>
    <header><h1>Zeniq - Freelance AI Assistant</h1></header>
    <nav>
        <?php if (isLoggedIn()): ?>
            <a href="zeniq.php?action=profile">Profile</a>
            <a href="zeniq.php?action=tasks">Tasks</a>
            <a href="zeniq.php?action=companies">Companies</a>
            <a href="zeniq.php?action=payments">Payments & Rewards</a>
            <a href="zeniq.php?action=ai">AI Assistant</a>
            <a href="zeniq.php?action=logout" onclick="return confirm('Logout?')">Logout</a>
        <?php else: ?>
            <a href="zeniq.php?action=login">Login</a>
            <a href="zeniq.php?action=register">Register</a>
            <a href="zeniq.php?action=companies">Companies</a>
        <?php endif; ?>
    </nav>
    <main>
        <p>Welcome to Zeniq, your freelancing AI assistant platform!</p>
        <?php if (!isLoggedIn()): ?>
            <p>Please <a href="zeniq.php?action=login">login</a> or <a href="zeniq.php?action=register">register</a> to continue.</p>
        <?php else:
            $user = getUser();
            ?>
            <h2>Hello, <?php echo h($user['full_name'] ?: $user['username']); ?>!</h2>
            <p>Your reward points: <?php echo h($user['rewards']); ?></p>
        <?php endif; ?>
    </main>
</body>
</html>

    <?php
}

function renderLoginForm() {
    ?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Zeniq - Login</title>
    <style><?php echo cssStyle(); ?></style>
</head>
<body>
    <header><h1>Login to Zeniq</h1></header>
    <main>
        <form method="POST" action="zeniq.php?action=login" class="form-box">
            <label>Username or Email:
                <input type="text" name="username" required autofocus>
            </label>
            <label>Password:
                <input type="password" name="password" required>
            </label>
            <input type="submit" value="Login">
        </form>
        <p>No account? <a href="zeniq.php?action=register">Register here</a>.</p>
    </main>
</body>
</html>

    <?php
}

function renderRegisterForm() {
    ?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Zeniq - Register</title>
    <style><?php echo cssStyle(); ?></style>
</head>
<body>
    <header><h1>Register for Zeniq</h1></header>
    <main>
        <form method="POST" action="zeniq.php?action=register" class="form-box">
            <label>Username:
                <input type="text" name="username" required autofocus minlength="3" maxlength="50">
            </label>
            <label>Email:
                <input type="email" name="email" required>
            </label>
            <label>Password:
                <input type="password" name="password" required minlength="6">
            </label>
            <input type="submit" value="Register">
        </form>
        <p>Already have an account? <a href="zeniq.php?action=login">Login here</a>.</p>
    </main>
</body>
</html>

    <?php
}

function renderProfile($pdo) {
    $user = getUser();

    // Fetch user's bank accounts
    $stmt = $pdo->prepare("SELECT * FROM bank_accounts WHERE user_id = ?");
    $stmt->execute([$user['id']]);
    $bankAccounts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    ?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Zeniq - Profile</title>
    <style><?php echo cssStyle(); ?></style>
</head>
<body>
    <header><h1>Your Profile</h1></header>
    <nav>
        <a href="zeniq.php">Home</a> |
        <a href="zeniq.php?action=tasks">Tasks</a> |
        <a href="zeniq.php?action=companies">Companies</a> |
        <a href="zeniq.php?action=payments">Payments</a> |
        <a href="zeniq.php?action=ai">AI Assistant</a> |
        <a href="zeniq.php?action=logout" onclick="return confirm('Logout?')">Logout</a>
    </nav>
    <main>
        <form method="POST" action="zeniq.php?action=profile" class="form-box">
            <label>Full Name:
                <input type="text" name="full_name" maxlength="100" value="<?php echo h($user['full_name']); ?>">
            </label>
            <label>Bio:
                <textarea name="bio" rows="3" maxlength="300"><?php echo h($user['bio']); ?></textarea>
            </label>
            <label>Interests (comma separated):
                <input type="text" name="interests" maxlength="255" value="<?php echo h($user['interests']); ?>">
            </label>
            <input type="submit" value="Update Profile">
        </form>

        <section>
            <h2>Bank Accounts</h2>
            <?php if ($bankAccounts): ?>
                <ul>
                    <?php foreach ($bankAccounts as $acc): ?>
                        <li><?php echo h($acc['bank_name']) . ' - ' . h($acc['account_number']) . ' (IFSC: ' . h($acc['ifsc']) . ')'; ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <p>No bank accounts linked.</p>
            <?php endif; ?>
            <form method="POST" action="zeniq.php?action=link_bank_account" class="form-box">
                <h3>Link a Bank Account</h3>
                <label>Bank Name:
                    <input type="text" name="bank_name" required maxlength="100">
                </label>
                <label>Account Number:
                    <input type="text" name="account_number" required maxlength="50">
                </label>
                <label>IFSC Code:
                    <input type="text" name="ifsc" required maxlength="20">
                </label>
                <input type="submit" value="Link Bank Account">
            </form>
        </section>
    </main>
</body>
</html>
    <?php
}

function renderCompanies($pdo) {
    // Fetch companies
    $stmt = $pdo->query("SELECT * FROM companies ORDER BY name ASC LIMIT 100");
    $companies = $stmt->fetchAll(PDO::FETCH_ASSOC);
    ?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Zeniq - Companies</title>
  <style><?php echo cssStyle(); ?></style>
</head>
<body>
  <header><h1>Indian Companies</h1></header>
  <nav>
    <?php if (isLoggedIn()): ?>
      <a href="zeniq.php">Home</a> |
      <a href="zeniq.php?action=profile">Profile</a> |
      <a href="zeniq.php?action=tasks">Tasks</a> |
      <a href="zeniq.php?action=payments">Payments</a> |
      <a href="zeniq.php?action=ai">AI Assistant</a> |
      <a href="zeniq.php?action=logout" onclick="return confirm('Logout?')">Logout</a>
    <?php else: ?>
      <a href="zeniq.php?action=login">Login</a> |
      <a href="zeniq.php?action=register">Register</a>
    <?php endif; ?>
  </nav>
  <main>
    <?php if (empty($companies)): ?>
      <p>No companies found.</p>
      <p>If you are admin, <a href="zeniq.php?action=seed_companies">Seed sample companies</a>.</p>
    <?php else: ?>
      <ul class="company-list">
        <?php foreach ($companies as $c): ?>
          <li>
            <h3><?php echo h($c['name']); ?></h3>
            <p><strong>Industry:</strong> <?php echo h($c['industry']); ?><br />
            <strong>Location:</strong> <?php echo h($c['location']); ?></p>
            <p><?php echo h($c['description']); ?></p>
            <?php if ($c['website']): ?>
              <p><a href="<?php echo h($c['website']); ?>" target="_blank" rel="noopener">Website</a></p>
            <?php endif; ?>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </main>
</body>
</html>

    <?php
}

function renderTasks($pdo) {
    // Fetch open tasks
    $stmt = $pdo->prepare("SELECT * FROM tasks WHERE status = 'open' LIMIT 20");
    $stmt->execute();
    $tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Fetch user's assigned tasks
    $stmt2 = $pdo->prepare("SELECT * FROM tasks WHERE assigned_to = ? AND status != 'completed'");
    $stmt2->execute([$_SESSION['user_id']]);
    $assignedTasks = $stmt2->fetchAll(PDO::FETCH_ASSOC);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Assign task
        $task_id = (int) ($_POST['task_id'] ?? 0);
        if ($task_id) {
            // Check task open
            $stmtCheck = $pdo->prepare("SELECT * FROM tasks WHERE id = ? AND status = 'open'");
            $stmtCheck->execute([$task_id]);
            if ($stmtCheck->fetch()) {
                $stmtAssign = $pdo->prepare("UPDATE tasks SET assigned_to = ?, status = 'assigned' WHERE id = ?");
                $stmtAssign->execute([$_SESSION['user_id'], $task_id]);
                echo "<p class='success'>Task assigned to you.</p>";
                redirect('zeniq.php?action=tasks');
            } else {
                echo "<p class='error'>Task not available.</p>";
            }
        }
    }

    ?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Zeniq - Freelancing Tasks</title>
  <style><?php echo cssStyle(); ?></style>
</head>
<body>
  <header><h1>Freelance Tasks</h1></header>
  <nav>
    <a href="zeniq.php">Home</a> |
    <a href="zeniq.php?action=profile">Profile</a> |
    <a href="zeniq.php?action=companies">Companies</a> |
    <a href="zeniq.php?action=payments">Payments</a> |
    <a href="zeniq.php?action=ai">AI Assistant</a> |
    <a href="zeniq.php?action=logout" onclick="return confirm('Logout?')">Logout</a>
  </nav>
  <main>
    <h2>Open Tasks</h2>
    <?php if (empty($tasks)): ?>
      <p>No open tasks available at the moment.</p>
    <?php else: ?>
      <ul>
      <?php foreach ($tasks as $t): ?>
        <li>
          <h3><?php echo h($t['title']); ?></h3>
          <p><?php echo h($t['description']); ?></p>
          <p>Reward: <?php echo h($t['reward_points']); ?> points</p>
          <form method="POST" style="display:inline;">
            <input type="hidden" name="task_id" value="<?php echo h($t['id']); ?>">
            <input type="submit" value="Assign to Me">
          </form>
        </li>
      <?php endforeach; ?>
      </ul>
    <?php endif; ?>

    <h2>Your Assigned Tasks</h2>
    <?php if (empty($assignedTasks)): ?>
      <p>You have no assigned tasks currently.</p>
    <?php else: ?>
      <ul>
      <?php foreach ($assignedTasks as $t): ?>
        <li>
          <h3><?php echo h($t['title']); ?></h3>
          <p><?php echo h($t['description']); ?></p>
          <p>Status: <?php echo h($t['status']); ?></p>
          <p>Reward: <?php echo h($t['reward_points']); ?> points</p>
        </li>
      <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </main>
</body>
</html>

    <?php
}

function renderPayments($pdo) {
    $user = getUser();

    // Dummy payment form - no actual payment processing for demo
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $amount = floatval($_POST['amount'] ?? 0);
        if ($amount > 0) {
            $rewardPoints = floor($amount / 10);
            // Update rewards
            $stmt = $pdo->prepare("UPDATE users SET rewards = rewards + ? WHERE id = ?");
            $stmt->execute([$rewardPoints, $user['id']]);
            // Insert payment record
            $stmt2 = $pdo->prepare("INSERT INTO payments (user_id, amount, reward_points_earned) VALUES (?, ?, ?)");
            $stmt2->execute([$user['id'], $amount, $rewardPoints]);
            echo "<p class='success'>Payment successful! You earned $rewardPoints reward points.</p>";
            redirect('zeniq.php?action=payments');
        } else {
            echo "<p class='error'>Please enter a valid amount.</p>";
        }
    }

    // Fetch payment history
    $stmt = $pdo->prepare("SELECT * FROM payments WHERE user_id = ? ORDER BY payment_date DESC LIMIT 10");
    $stmt->execute([$user['id']]);
    $payments = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Fetch updated user rewards
    $user = getUser();

    ?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Zeniq - Payments & Rewards</title>
    <style><?php echo cssStyle(); ?></style>
</head>
<body>
  <header><h1>Payments & Rewards</h1></header>
  <nav>
    <a href="zeniq.php">Home</a> |
    <a href="zeniq.php?action=profile">Profile</a> |
    <a href="zeniq.php?action=tasks">Tasks</a> |
    <a href="zeniq.php?action=companies">Companies</a> |
    <a href="zeniq.php?action=ai">AI Assistant</a> |
    <a href="zeniq.php?action=logout" onclick="return confirm('Logout?')">Logout</a>
  </nav>
  <main>
    <h2>Your Rewards: <?php echo h($user['rewards']); ?> points</h2>
    <form method="POST" class="form-box">
      <label>Make a Payment (simulate):
        <input type="number" name="amount" min="1" step="any" required>
      </label>
      <input type="submit" value="Pay">
    </form>
    <h3>Payment History</h3>
    <?php if ($payments): ?>
      <ul>
        <?php foreach ($payments as $p): ?>
          <li>
            Date: <?php echo h($p['payment_date']); ?> - Amount: ₹<?php echo h($p['amount']); ?> - Rewards Earned: <?php echo h($p['reward_points_earned']); ?>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php else: ?>
      <p>No payment records found.</p>
    <?php endif; ?>
  </main>
</body>
</html>

    <?php
}

function renderAI($pdo) {
    // Show users with common interests except self
    $user = getUser();
    $interests = array_filter(array_map('trim', explode(',', strtolower($user['interests'] ?? ''))));

    $matchingUsers = [];
    if ($interests) {
        $placeholders = implode(',', array_fill(0, count($interests), '?'));
        $sql = "SELECT * FROM users WHERE id != ? AND (";
        foreach ($interests as $i => $interest) {
            $sql .= "LOWER(interests) LIKE ?";
            if ($i < count($interests) -1) $sql .= " OR ";
        }
        $sql .= ") LIMIT 20";
        $params = array_merge([$user['id']], array_map(fn($i) => "%$i%", $interests));
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $matchingUsers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    ?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Zeniq - AI Assistant</title>
  <style><?php echo cssStyle(); ?></style>
</head>
<body>
  <header><h1>AI Assistant - User Suggestions</h1></header>
  <nav>
    <a href="zeniq.php">Home</a> |
    <a href="zeniq.php?action=profile">Profile</a> |
    <a href="zeniq.php?action=tasks">Tasks</a> |
    <a href="zeniq.php?action=companies">Companies</a> |
    <a href="zeniq.php?action=payments">Payments</a> |
    <a href="zeniq.php?action=logout" onclick="return confirm('Logout?')">Logout</a>
  </nav>
  <main>
    <?php if ($interests): ?>
        <h2>Users sharing your interests (<?php echo h(implode(', ', $interests)); ?>)</h2>
        <?php if (!empty($matchingUsers)): ?>
            <ul>
            <?php foreach ($matchingUsers as $mu): ?>
                <li><strong><?php echo h($mu['full_name'] ?: $mu['username']); ?></strong> | Interests: <?php echo h($mu['interests']); ?></li>
            <?php endforeach; ?>
            </ul>
        <?php else: ?>
            <p>No users match your interests yet. Keep your profile updated!</p>
        <?php endif; ?>
    <?php else: ?>
        <p>You have not set any interests. Please <a href="zeniq.php?action=profile">update your profile</a>.</p>
    <?php endif; ?>
  </main>
</body>
</html>

    <?php
}

function seedCompanies($pdo) {
    $companies = [
        ['name'=>'Tata Consultancy Services','description'=>'Global IT services and consulting','industry'=>'IT','location'=>'Mumbai','website'=>'https://www.tcs.com'],
        ['name'=>'Reliance Industries','description'=>'Conglomerate with diverse businesses','industry'=>'Conglomerate','location'=>'Mumbai','website'=>'https://www.ril.com'],
        ['name'=>'Infosys','description'=>'IT services and consulting','industry'=>'IT','location'=>'Bangalore','website'=>'https://www.infosys.com'],
        ['name'=>'Wipro','description'=>'IT services and consulting','industry'=>'IT','location'=>'Bangalore','website'=>'https://www.wipro.com'],
        ['name'=>'HDFC Bank','description'=>'Banking and financial services','industry'=>'Banking','location'=>'Mumbai','website'=>'https://www.hdfcbank.com'],
        ['name'=>'ICICI Bank','description'=>'Banking and financial services','industry'=>'Banking','location'=>'Mumbai','website'=>'https://www.icicibank.com'],
        ['name'=>'Bharti Airtel','description'=>'Telecommunications services','industry'=>'Telecom','location'=>'New Delhi','website'=>'https://www.airtel.in'],
        ['name'=>'Larsen & Toubro','description'=>'Engineering and construction','industry'=>'Infrastructure','location'=>'Mumbai','website'=>'https://www.larsentoubro.com'],
    ];
    $stmt = $pdo->prepare("INSERT INTO companies (name, description, industry, location, website) VALUES (?, ?, ?, ?, ?)");
    foreach ($companies as $c) {
        $stmt->execute([$c['name'], $c['description'], $c['industry'], $c['location'], $c['website']]);
    }
}

function cssStyle() {
    return <<<CSS
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #f0f4f8;
        color: #333;
        margin: 0; padding: 0;
    }
    header {
        background: #0077cc;
        color: white;
        padding: 1rem;
        text-align: center;
    }
    nav {
        background: #005fa3;
        padding: 0.5rem;
        text-align: center;
    }
    nav a {
        color: white;
        margin: 0 0.75rem;
        text-decoration: none;
        font-weight: bold;
    }
    nav a:hover {
        text-decoration: underline;
    }
    main {
        max-width: 700px;
        margin: 1rem auto;
        padding: 1rem;
        background: white;
        border-radius: 8px;
        box-shadow: 0 0 8px rgba(0,0,0,0.1);
    }
    form.form-box {
        display: flex;
        flex-direction: column;
    }
    form.form-box label {
        margin-bottom: 1rem;
    }
    form.form-box input[type="text"],
    form.form-box input[type="email"],
    form.form-box input[type="password"],
    form.form-box textarea,
    form.form-box input[type="number"] {
        width: 100%;
        padding: 0.5rem;
        border: 1px solid #aaa;
        border-radius: 4px;
        font-size: 1rem;
        box-sizing: border-box;
    }
    form.form-box input[type="submit"] {
        background: #0077cc;
        color: white;
        border: none;
        padding: 0.75rem;
        font-size: 1rem;
        border-radius: 4px;
        cursor: pointer;
    }
    form.form-box input[type="submit"]:hover {
        background: #005fa3;
    }
    .error {
        background: #ffdddd;
        border: 1px solid #ff5c5c;
        padding: 0.75rem;
        margin-bottom: 1rem;
        border-radius: 4px;
        color: #900;
    }
    .success {
        background: #ddffdd;
        border: 1px solid #5cff5c;
        padding: 0.75rem;
        margin-bottom: 1rem;
        border-radius: 4px;
        color: #090;
    }
    ul.company-list {
        list-style-type: none;
        padding-left: 0;
    }
    ul.company-list li {
        border-bottom: 1px solid #ddd;
        padding: 0.5rem 0;
    }
CSS;
}
?>
</content>
</create_file>

<attempt_completion>