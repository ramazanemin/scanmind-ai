// Acme AI - bundled config (ScanMind demo fixture).
// The keys below are the classic AWS documentation examples - not real credentials.

const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

function renderComments(comments) {
  document.write(comments.map(function (c) {
    return "<div>" + c + "</div>";
  }).join(""));
  eval("window.comments = " + JSON.stringify(comments));
}
