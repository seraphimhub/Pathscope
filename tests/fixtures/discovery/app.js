// Static discovery fixture with annotated ground truth.
// Commented examples must never become findings:
// fetch("/api/v1/commented-out");
/* fetch("/api/v1/block-commented"); */

const users = "/api/v1/users";
const posts = '/api/v1/posts';
const duplicate = "/api/v1/users";
const apiBase = "/api/v2";
const invoices = "/api/v2" + "/invoices";
const absolute = "https://api.example.com/v2/orders";
const query = "/search?q=1";
const asset = "/static/app.js";
const sourceMap = "/static/app.js.map";
const relative = "api/v1/relative";
const fake = "not-a-path";

var apiKey = "EXAMPLE_PLACEHOLDER_VALUE_123";
var token = "YOUR_TOKEN_HERE";
// password = "hunter2"
fetch("/api/v1/health");
