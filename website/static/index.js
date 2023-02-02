function deleteNote(appId) {
  fetch("/delete-note", {
    method: "POST",
    body: JSON.stringify({ appId: appId }),
  }).then((_res) => {
    window.location.href = "/admin";
  });
}
