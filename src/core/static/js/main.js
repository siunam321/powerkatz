function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const FIVE_SECONDS = 5000;
const toastElList = document.querySelectorAll('.toast');
const toastList = [...toastElList].map(toastEl => new bootstrap.Toast(toastEl, {"delay": FIVE_SECONDS}));
const [succeedToast, failedToast, pendingToast] = toastList;

const toastStatusBadges = toastList.map(toast => toast._element.children[1]);
const [succeedToastStatusBadge, failedToastStatusBadge, pendingToastStatusBadge] = toastStatusBadges;

const toastBodies = toastList.map(toast => toast._element.children[2]);
const [succeedToastBody, failedToastBody, pendingToastBody] = toastBodies;

function createToast(status, message) {
    if (status === "Succeed") {
        var originalToast = document.getElementById("succeedToast");
        succeedToastBody.innerText = message;
    } else if (status === "Failed") {
        var originalToast = document.getElementById("failedToast");
        failedToastBody.innerText = message;
    } else if (status === "Pending") {
        var originalToast = document.getElementById("pendingToast");
        pendingToastBody.innerText = message;
    }

    var toastContainer = document.getElementById("toastContainer");

    var toast = originalToast.cloneNode(true);
    toastContainer.appendChild(toast);

    var toastID = "toast" + Math.floor(Math.random() * 100000);
    toast.setAttribute("id", toastID);

    var bsToast = new bootstrap.Toast(toast, {"delay": FIVE_SECONDS});
    bsToast.show();

    setTimeout(function() {
        toast.remove();
    }, FIVE_SECONDS);
}

async function registerParameters() {
    var submitButton = document.getElementById("submitButton");
    submitButton.disabled = true;

    const targetIpAddress = document.getElementById("targetIpAddress").value;
    const attackerIpAddress = document.getElementById("attackerIpAddress").value;
    const errorAlert = document.getElementById("error");
    const errorAlertHeading = document.getElementById("failedAlertHeading");
    const errorAlertPTag = document.getElementById("failedAlertPTag");
    const succeedAlert = document.getElementById("succeed");
    const succeedAlertHeading = document.getElementById("succeedAlertHeading");
    const succeedAlertPTag = document.getElementById("succeedAlertPTag");
    const pendingAlert = document.getElementById("pending");
    const pendingAlertHeading = document.getElementById("pendingAlertHeading");
    const pendingAlertPTag = document.getElementById("pendingAlertPTag");

    succeedAlert.style.display = "none";
    succeedAlertHeading.innerText = "";
    succeedAlertPTag.innerText = "";
    errorAlert.style.display = "none";
    errorAlertHeading.innerText = "";
    errorAlertPTag.innerText = "";
    pendingAlert.style.display = "";
    pendingAlertHeading.innerText = "Status: Pending";
    pendingAlertPTag.innerText = "Setting up the Flask web app and the Powerkatz Server Listener...";
    createToast("Pending", "Setting up the Flask web app and the Powerkatz Server Listener...");

    var bodyJsonData = {};

    var allSessionDivs = document.querySelectorAll("div[name=session]");
    allSessionDivs.forEach((sessionDiv) => {
        if (sessionDiv.id == "selectSession") {
            return;
        }

        var sessionTargetIpAddress = sessionDiv.dataset.targetipaddress;
        var currentSessionRadioButtons = document.querySelectorAll(`input[type="radio"][name="currentSession-${sessionTargetIpAddress}"]`);
        var currentSession;
        currentSessionRadioButtons.forEach((radioButton) => {
            if (radioButton.checked) {
                currentSession = radioButton.value;
            }
        });

        var shellType = sessionDiv.querySelector("select[id=shellType]").value;
        var targetPortNumber = sessionDiv.querySelector("input[name=listenerPortNumber]").value;

        var isOtherShell = currentSession === "shell" && shellType === "other";
        if (currentSession === "shell" && !isOtherShell) {
            bodyJsonData[sessionTargetIpAddress] = {
                "currentSession": currentSession,
                "attackerIpAddress": attackerIpAddress,
                "shellType": shellType,
                "targetPortNumber": targetPortNumber
            };
        } else if (currentSession === "rdpOrVnc" || isOtherShell) {
            if (isOtherShell) {
                bodyJsonData[sessionTargetIpAddress] = {
                    "currentSession": currentSession,
                    "attackerIpAddress": attackerIpAddress,
                    "shellType": shellType
                };
            } else {
                bodyJsonData[sessionTargetIpAddress] = {
                    "currentSession": currentSession,
                    "attackerIpAddress": attackerIpAddress
                };
            }
        } else {
            // current session is not selected
            bodyJsonData[sessionTargetIpAddress] = {
                "currentSession": "",
                "attackerIpAddress": attackerIpAddress
            };
        }
    });
    var bodyJsonData = JSON.stringify(bodyJsonData);

    var response = await fetch("/api/registerParameters", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: bodyJsonData,
    });
    var result = await response.json()
    let responseStatus = result["status"];
    if (responseStatus === "Failed") {
        succeedAlert.style.display = "none";
        succeedAlertHeading.innerText = "";
        succeedAlertPTag.innerText = "";
        errorAlert.style.display = "";
        errorAlertHeading.innerText = `Status: ${responseStatus}`;
        errorAlertPTag.innerText = result["message"];
        createToast(responseStatus, result["message"]);
        pendingAlert.style.display = "none";
        pendingAlertHeading.innerText = "";
        pendingAlertPTag.innerText = "";
        submitButton.disabled = false;
        return;
    }

    errorAlert.style.display = "none";
    errorAlertHeading.innerText = "";
    errorAlertPTag.innerText = "";
    pendingAlert.style.display = "none";
    pendingAlertHeading.innerText = "";
    pendingAlertPTag.innerText = "";
    succeedAlertHeading.innerText = `Status: ${responseStatus}`;
    succeedAlertPTag.innerText = result["message"];
    succeedAlertPTag.innerText += " Redirecting to the \"Automate Executor\" page in 3 seconds...";
    succeedAlert.style.display = "";
    createToast(responseStatus, result["message"] + " Redirecting to the \"Automate Executor\" page in 3 seconds...");
    await sleep(3000);
    document.location = "/automate-executor";
}

async function transferListener(submitButtonElement) {
    try {
        submitButtonElement.disabled = true;

        const errorAlert = document.getElementById("error");
        const errorAlertHeading = document.getElementById("failedAlertHeading");
        const errorAlertPTag = document.getElementById("failedAlertPTag");
        const succeedAlert = document.getElementById("succeed");
        const succeedAlertHeading = document.getElementById("succeedAlertHeading");
        const succeedAlertPTag = document.getElementById("succeedAlertPTag");
        const pendingAlert = document.getElementById("pending");
        const pendingAlertHeading = document.getElementById("pendingAlertHeading");
        const pendingAlertPTag = document.getElementById("pendingAlertPTag");

        succeedAlert.style.display = "none";
        succeedAlertHeading.innerText = "";
        succeedAlertPTag.innerText = "";
        errorAlert.style.display = "none";
        errorAlertHeading.innerText = "";
        errorAlertPTag.innerText = "";
        pendingAlert.style.display = "";
        pendingAlertHeading.innerText = "Status: Pending";
        pendingAlertPTag.innerText = "Setting up the Powerkatz Server Listener...";
        createToast("Pending", "Setting up the Powerkatz Server Listener...");

        var selectedTargetIpAddressDropdown = document.getElementById("selectedTargetIpAddressDropdown").value;
        var bodyData = {
            "targetIpAddress": selectedTargetIpAddressDropdown
        }
        var bodyJsonData = JSON.stringify(bodyData);
        
        var response = await fetch("/api/transferListener", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: bodyJsonData,
        });
        const result = await response.json();
        let responseStatus = result["status"];
        if (responseStatus === "Failed") {
            succeedAlert.style.display = "none";
            succeedAlertHeading.innerText = "";
            succeedAlertPTag.innerText = "";
            errorAlert.style.display = "";
            errorAlertHeading.innerText = `Status: ${responseStatus}`;
            errorAlertPTag.innerText = result["message"];
            pendingAlert.style.display = "none";
            pendingAlertHeading.innerText = "";
            pendingAlertPTag.innerText = "";
            createToast(responseStatus, result["message"]);
            submitButtonElement.disabled = false;
            return;
        };

        errorAlert.style.display = "none";
        errorAlertHeading.innerText = "";
        errorAlertPTag.innerText = "";
        pendingAlert.style.display = "none";
        pendingAlertHeading.innerText = "";
        pendingAlertPTag.innerText = "";
        succeedAlert.style.display = "";
        succeedAlertHeading.innerText = `Status: ${responseStatus}`;
        succeedAlertPTag.innerText = result["message"];
        createToast(responseStatus, result["message"]);

        var statusTexts = document.querySelectorAll("span[name=statusText]");
        statusTexts.forEach((statusText) => {
            if (statusText.dataset.targetipaddress === selectedTargetIpAddressDropdown) {
                statusText.setAttribute("class", "badge rounded-pill text-bg-success fs-4");
                statusText.innerText = "Up and running";
            }
        });
        var stopButtons = document.querySelectorAll("button[name=stopButton]");
        stopButtons.forEach((stopButton) => {
            if (stopButton.dataset.targetipaddress === selectedTargetIpAddressDropdown) {
                stopButton.disabled = false;
                stopButton.setAttribute("class", "btn btn-success");
            }
        });
        var startButtons = document.querySelectorAll("button[name=startButton]");
        startButtons.forEach((startButton) => {
            if (startButton.dataset.targetipaddress === selectedTargetIpAddressDropdown) {
                startButton.disabled = true;
                startButton.setAttribute("class", "btn btn-danger");
            }
        });
    } catch (error) {
        console.error("Error:", error);
    }
}

async function stopListener(submitButtonElement) {
    try {
        submitButtonElement.disabled = true;

        const errorAlert = document.getElementById("error");
        const errorAlertHeading = document.getElementById("failedAlertHeading");
        const errorAlertPTag = document.getElementById("failedAlertPTag");
        const succeedAlert = document.getElementById("succeed");
        const succeedAlertHeading = document.getElementById("succeedAlertHeading");
        const succeedAlertPTag = document.getElementById("succeedAlertPTag");

        var selectedTargetIpAddressDropdown = document.getElementById("selectedTargetIpAddressDropdown").value;
        var bodyData = {
            "targetIpAddress": selectedTargetIpAddressDropdown
        }
        var bodyJsonData = JSON.stringify(bodyData);

        var response = await fetch("/api/stopListener", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: bodyJsonData,
        });
        const result = await response.json();
        let responseStatus = result["status"];
        if (responseStatus === "Failed") {
            succeedAlert.style.display = "none";
            succeedAlertHeading.innerText = "";
            succeedAlertPTag.innerText = "";
            errorAlert.style.display = "";
            errorAlertHeading.innerText = `Status: ${responseStatus}`;
            errorAlertPTag.innerText = result["message"];
            createToast(responseStatus, result["message"]);
            submitButtonElement.disabled = false;
            return;
        };

        errorAlert.style.display = "none";
        errorAlertHeading.innerText = "";
        errorAlertPTag.innerText = "";
        succeedAlert.style.display = "";
        succeedAlertHeading.innerText = `Status: ${responseStatus}`;
        succeedAlertPTag.innerText = result["message"];
        createToast(responseStatus, result["message"]);

        var statusTexts = document.querySelectorAll("span[name=statusText]");
        statusTexts.forEach((statusText) => {
            if (statusText.dataset.targetipaddress === selectedTargetIpAddressDropdown) {
                statusText.setAttribute("class", "badge rounded-pill text-bg-danger fs-4");
                statusText.innerText = "Down";
            }
        });
        var stopButtons = document.querySelectorAll("button[name=stopButton]");
        stopButtons.forEach((stopButton) => {
            if (stopButton.dataset.targetipaddress === selectedTargetIpAddressDropdown) {
                stopButton.disabled = true;
                stopButton.setAttribute("class", "btn btn-danger");
            }
        });
        var startButtons = document.querySelectorAll("button[name=startButton]");
        startButtons.forEach((startButton) => {
            if (startButton.dataset.targetipaddress === selectedTargetIpAddressDropdown) {
                startButton.disabled = false;
                startButton.setAttribute("class", "btn btn-success");
            }
        });
    } catch (error) {
        console.error("Error:", error);
    }
}

async function enumerateComputerDomain() {
    try {
        const errorAlert = document.getElementById("error");
        const errorAlertHeading = document.getElementById("failedAlertHeading");
        const errorAlertPTag = document.getElementById("failedAlertPTag");
        const succeedAlert = document.getElementById("succeed");
        const succeedAlertHeading = document.getElementById("succeedAlertHeading");
        const succeedAlertPTag = document.getElementById("succeedAlertPTag");

        var targetIpAddresses = [];
        var targetIpAddressCheckBoxes = document.querySelectorAll("input[name=targetIpAddress]");
        targetIpAddressCheckBoxes.forEach((checkBox) => {
            if (checkBox.checked) {
                targetIpAddresses.push(checkBox.value);
            }
        });
        var bodyData = {
            "targetIpAddresses": targetIpAddresses
        }
        var bodyJsonData = JSON.stringify(bodyData);
        var response = await fetch("/api/enumerateComputerDomain", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: bodyJsonData,
        });
        const result = await response.json();
        let responseStatus = result["status"];
        if (responseStatus === "Failed") {
            succeedAlert.style.display = "none";
            succeedAlertHeading.innerText = "";
            succeedAlertPTag.innerText = "";
            errorAlert.style.display = "";
            errorAlertHeading.innerText = `Status: ${responseStatus}`;
            errorAlertPTag.innerText = result["message"];
            createToast(responseStatus, result["message"]);
            return;
        };

        errorAlert.style.display = "none";
        errorAlertHeading.innerText = "";
        errorAlertPTag.innerText = "";
        succeedAlert.style.display = "";
        succeedAlertHeading.innerText = `Status: ${responseStatus}`;
        succeedAlertPTag.innerText = result["message"];
        createToast(responseStatus, result["message"]);
    } catch (error) {
        console.error("Error:", error);
    }
}

// from https://html.spec.whatwg.org/multipage/input.html#fakepath-srsly
function extractFilename(path) {
  if (path.substr(0, 12) == "C:\\fakepath\\")
    return path.substr(12); // modern browser
  var x;
  x = path.lastIndexOf('/');
  if (x >= 0) // Unix-based path
    return path.substr(x+1);
  x = path.lastIndexOf('\\');
  if (x >= 0) // Windows-based path
    return path.substr(x+1);
  return path; // just the filename
}

async function updateSettings(){
    try {
        const errorAlert = document.getElementById("error");
        const errorAlertHeading = document.getElementById("failedAlertHeading");
        const errorAlertPTag = document.getElementById("failedAlertPTag");
        const succeedAlert = document.getElementById("succeed");
        const succeedAlertHeading = document.getElementById("succeedAlertHeading");
        const succeedAlertPTag = document.getElementById("succeedAlertPTag");

        var settings = {};
        var targetIpAddresses = document.getElementById("targetIpAddress").value;
        var splitedTargetIpAddresses = targetIpAddresses.split(/[;,]/g);

        var generalSettings = {}        
        var powerkatzListenerPortNumber = {};
        var currentSession = {};
        var shellListenerPortNumber = {};
        var shellType = {};
        var shellPid = {};
        var shellFd = {};
        var setupComplete = {};
        var powerkatzServerListenerStatus = {};
        splitedTargetIpAddresses.forEach((targetIpAddress) => {
            var powerkatzListenerPortNumberValue = document.getElementById("powerkatzListenerPortNumber").value;
            powerkatzListenerPortNumber[targetIpAddress] = powerkatzListenerPortNumberValue;

            var currentSessionRadioButtons = document.querySelectorAll(`input[type="radio"][name="session-${targetIpAddress}"]`);
            currentSessionRadioButtons.forEach((radioButton) => {
                if (radioButton.checked) {
                    currentSession[targetIpAddress] = radioButton.value;
                }
            });

            if (currentSession[targetIpAddress] == "shell") {
                var shellTypeValue = document.getElementById(`shellType-${targetIpAddress}`).value;
                shellType[targetIpAddress] = shellTypeValue;
                if (shellType !== "other") {
                    var shellListenerPortNumberValue = document.getElementById(`shellListenerPortNumber-${targetIpAddress}`).value;
                    var shellPidValue = document.getElementById(`shellPid-${targetIpAddress}`).value;
                    var shellFdValue = document.getElementById(`shellFd-${targetIpAddress}`).value;
                    shellListenerPortNumber[targetIpAddress] = shellListenerPortNumberValue;
                    shellPid[targetIpAddress] = shellPidValue;
                    shellFd[targetIpAddress] = shellFdValue;
                }
            }

            var setupCompletionValue = document.getElementById("setupCompletion").value;
            setupComplete[targetIpAddress] = setupCompletionValue;
            var listenerStatusValue = document.getElementById("listenerStatus").value;
            powerkatzServerListenerStatus[targetIpAddress] = listenerStatusValue;
        });

        splitedTargetIpAddresses.forEach((targetIpAddress) => {
            if (currentSession[targetIpAddress] === "shell") {
                if (shellType[targetIpAddress] !== "other") {
                    generalSettings[targetIpAddress] = {
                        "powerkatzListenerPortNumber": powerkatzListenerPortNumber[targetIpAddress],
                        "currentSession": currentSession[targetIpAddress],
                        "listenerPortNumber": shellListenerPortNumber[targetIpAddress],
                        "shellType": shellType[targetIpAddress],
                        "shellPid": shellPid[targetIpAddress],
                        "processFd": shellFd[targetIpAddress],
                        "setupComplete": setupComplete[targetIpAddress],
                        "powerkatzServerListenerStatus": powerkatzServerListenerStatus[targetIpAddress]
                    };
                } else {
                    generalSettings[targetIpAddress] = {
                        "powerkatzListenerPortNumber": powerkatzListenerPortNumber[targetIpAddress],
                        "currentSession": currentSession[targetIpAddress],
                        "shellType": shellType[targetIpAddress],
                        "setupComplete": setupComplete[targetIpAddress],
                        "powerkatzServerListenerStatus": powerkatzServerListenerStatus[targetIpAddress]
                    };
                }
            } else if (currentSession[targetIpAddress] === "rdpOrVnc") {
                generalSettings[targetIpAddress] = {
                    "powerkatzListenerPortNumber": powerkatzListenerPortNumber[targetIpAddress],
                    "currentSession": currentSession[targetIpAddress],
                    "shellType": "N/A",
                    "setupComplete": setupComplete[targetIpAddress],
                    "powerkatzServerListenerStatus": powerkatzServerListenerStatus[targetIpAddress]
                };
            }
        });
        settings["generalSettings"] = generalSettings;

        var otherGeneralSettings = {};
        var passwordCrackingWordlistValue = document.getElementById("formFile").value;
        var filename = extractFilename(passwordCrackingWordlistValue);
        otherGeneralSettings["passwordCrackingWordlist"] = filename;
        var attackerIpAddressValue = document.getElementById("attackerIpAddress").value;
        otherGeneralSettings["attackerIpAddress"] = attackerIpAddressValue;

        settings["otherGeneralSettings"] = otherGeneralSettings;

        var bodyJsonData = JSON.stringify(settings);
        var response = await fetch("/api/updateSettings", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: bodyJsonData,
        });
        const result = await response.json();
        let responseStatus = result["status"];
        if (responseStatus === "Failed") {
            succeedAlert.style.display = "none";
            succeedAlertHeading.innerText = "";
            succeedAlertPTag.innerText = "";
            errorAlert.style.display = "";
            errorAlertHeading.innerText = `Status: ${responseStatus}`;
            errorAlertPTag.innerText = result["message"];
            createToast(responseStatus, result["message"]);
            return;
        };

        errorAlert.style.display = "none";
        errorAlertHeading.innerText = "";
        errorAlertPTag.innerText = "";
        succeedAlert.style.display = "";
        succeedAlertHeading.innerText = `Status: ${responseStatus}`;
        succeedAlertPTag.innerText = result["message"];
        createToast(responseStatus, result["message"]);
    } catch (error) {
        console.log("Error:", error);
    }
}

async function importSettings(submitButtonElement, isFromInitialSetup = false) {
    submitButtonElement.disabled = true;
    const errorAlertModal = document.getElementById("errorModal");
    const errorAlertHeadingModal = document.getElementById("failedAlertHeadingModal");
    const errorAlertPTagModal = document.getElementById("failedAlertPTagModal");
    const succeedAlertModal = document.getElementById("succeedModal");
    const succeedAlertHeadingModal = document.getElementById("succeedAlertHeadingModal");
    const succeedAlertPTagModal = document.getElementById("succeedAlertPTagModal");
    const pendingAlertModal = document.getElementById("pendingModal");
    const pendingAlertHeadingModal = document.getElementById("pendingAlertHeadingModal");
    const pendingAlertPTagModal = document.getElementById("pendingAlertPTagModal");
    const importSettingsFileInput = document.getElementById("importSettingsFileInput");

    succeedAlertModal.style.display = "none";
    succeedAlertHeadingModal.innerText = "";
    succeedAlertPTagModal.innerText = "";
    errorAlertModal.style.display = "none";
    errorAlertHeadingModal.innerText = "";
    errorAlertPTagModal.innerText = "";
    pendingAlertModal.style.display = "";
    pendingAlertHeadingModal.innerText = "Status: Pending";
    pendingAlertPTagModal.innerText = "Importing settings...";
    createToast("Pending", "Importing settings...");

    var formData = new FormData();
    formData.append('settingsFile', importSettingsFileInput.files[0]);
    
    var response = await fetch("/api/importSettings", {
        method: "POST",
        body: formData,
    });
    const result = await response.json();
    let responseStatus = result["status"];
    if (responseStatus === "Failed") {
        succeedAlertModal.style.display = "none";
        succeedAlertHeadingModal.innerText = "";
        succeedAlertPTagModal.innerText = "";
        pendingAlertModal.style.display = "none";
        pendingAlertHeadingModal.innerText = "";
        pendingAlertPTagModal.innerText = "";
        errorAlertModal.style.display = "";
        errorAlertHeadingModal.innerText = `Status: ${responseStatus}`;
        errorAlertPTagModal.innerText = result["message"];
        createToast(responseStatus, result["message"]);
        submitButtonElement.disabled = false;
        return;
    };

    errorAlertModal.style.display = "none";
    errorAlertHeadingModal.innerText = "";
    errorAlertPTagModal.innerText = "";
    pendingAlertModal.style.display = "none";
    pendingAlertHeadingModal.innerText = "";
    pendingAlertPTagModal.innerText = "";
    succeedAlertModal.style.display = "";
    succeedAlertHeadingModal.innerText = `Status: ${responseStatus}`;
    succeedAlertPTagModal.innerText = result["message"];
    createToast(responseStatus, result["message"]);
    submitButtonElement.disabled = false;
    if (isFromInitialSetup) {
        succeedAlertPTagModal.innerText += " Redirecting to the \"Dashboard\" page in 3 seconds...";
        await sleep(3000);
        document.location = "/?isFromInitialSetup=1";
    }
}

async function importHistories(importHistorySubmitButton) {
    importHistorySubmitButton.disabled = true;
    const errorAlertModal = document.getElementById("errorModal");
    const errorAlertHeadingModal = document.getElementById("failedAlertHeadingModal");
    const errorAlertPTagModal = document.getElementById("failedAlertPTagModal");
    const succeedAlertModal = document.getElementById("succeedModal");
    const succeedAlertHeadingModal = document.getElementById("succeedAlertHeadingModal");
    const succeedAlertPTagModal = document.getElementById("succeedAlertPTagModal");
    const pendingAlertModal = document.getElementById("pendingModal");
    const pendingAlertHeadingModal = document.getElementById("pendingAlertHeadingModal");
    const pendingAlertPTagModal = document.getElementById("pendingAlertPTagModal");
    const importHistoryFileInput = document.getElementById("importHistoryFileInput");

    succeedAlertModal.style.display = "none";
    succeedAlertHeadingModal.innerText = "";
    succeedAlertPTagModal.innerText = "";
    errorAlertModal.style.display = "none";
    errorAlertHeadingModal.innerText = "";
    errorAlertPTagModal.innerText = "";
    pendingAlertModal.style.display = "";
    pendingAlertHeadingModal.innerText = "Status: Pending";
    pendingAlertPTagModal.innerText = "Importing history/histories...";
    createToast("Pending", "Importing history/histories...");

    var formData = new FormData();
    var files = importHistoryFileInput.files;
    for (var i = 0; i < files.length; i++) {
        formData.append('historyFiles', files[i]);
    };
    
    var response = await fetch("/api/importHistories", {
        method: "POST",
        body: formData,
    });
    const result = await response.json();
    let responseStatus = result["status"];
    if (responseStatus === "Failed") {
        succeedAlertModal.style.display = "none";
        succeedAlertHeadingModal.innerText = "";
        succeedAlertPTagModal.innerText = "";
        pendingAlertModal.style.display = "none";
        pendingAlertHeadingModal.innerText = "";
        pendingAlertPTagModal.innerText = "";
        errorAlertModal.style.display = "";
        errorAlertHeadingModal.innerText = `Status: ${responseStatus}`;
        errorAlertPTagModal.innerText = result["message"];
        createToast(responseStatus, result["message"]);
        importHistorySubmitButton.disabled = false;
        return;
    };

    errorAlertModal.style.display = "none";
    errorAlertHeadingModal.innerText = "";
    errorAlertPTagModal.innerText = "";
    pendingAlertModal.style.display = "none";
    pendingAlertHeadingModal.innerText = "";
    pendingAlertPTagModal.innerText = "";
    succeedAlertModal.style.display = "";
    succeedAlertHeadingModal.innerText = `Status: ${responseStatus}`;
    succeedAlertPTagModal.innerText = result["message"];
    createToast(responseStatus, result["message"]);
    importHistorySubmitButton.disabled = false;
}