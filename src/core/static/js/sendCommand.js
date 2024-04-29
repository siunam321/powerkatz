function getTargetIpAddresses() {
    var targetIpAddresses = [];
    var targetIpAddressCheckBoxes = document.querySelectorAll("input[name=targetIpAddress]");
    targetIpAddressCheckBoxes.forEach((checkBox) => {
        if (checkBox.checked) {
            targetIpAddresses.push(checkBox.value);
        }
    });

    return targetIpAddresses;
}

function prepareJsonData(command, formattedFunctionName) {
    var targetIpAddresses = [];
    if (formattedFunctionName === "Password Hash Authentication (Pass-the-Hash)") {
        var lateralMovementTargetIpAddressCheckboxes = document.querySelectorAll("input[name=lateralMovementTargets]");
        lateralMovementTargetIpAddressCheckboxes.forEach((checkBox) => {
            if (checkBox.checked) {
                targetIpAddresses.push(checkBox.value);
            }
        });
    } else {
        targetIpAddresses = getTargetIpAddresses();
    }

    var bodyData = {
        "command": command,
        "targetIpAddresses": targetIpAddresses,
        "formattedFunctionName": formattedFunctionName
    }
    var jsonBodyData = JSON.stringify(bodyData);
    return jsonBodyData;
}

function prepareAgentJsonData(command, agentIds, formattedFunctionName) {
    var bodyData = {
        "agentCommand": command,
        "agentIds": agentIds,
        "formattedFunctionName": formattedFunctionName
    }
    var jsonBodyData = JSON.stringify(bodyData);
    return jsonBodyData;
}

async function displayPendingMessage(targetIpAddresses) {
    const executeButton = document.getElementById("executeButton");
    executeButton.disabled = true;

    targetIpAddresses.forEach((targetIpAddress) => {
        var mimikatzCommandCodeBlock = document.getElementById(`mimikatzCommand-${targetIpAddress}`);
        var command = mimikatzCommandCodeBlock.innerText;
        hljs.highlightElement(mimikatzCommandCodeBlock);

        var errorAlert = document.getElementById(`error-${targetIpAddress}`);
        var errorAlertHeading = document.getElementById(`failedAlertHeading-${targetIpAddress}`);
        var errorAlertPTag = document.getElementById(`failedAlertPTag-${targetIpAddress}`);
        var succeedAlert = document.getElementById(`succeed-${targetIpAddress}`);
        var succeedAlertHeading = document.getElementById(`succeedAlertHeading-${targetIpAddress}`);
        var succeedAlertPTag = document.getElementById(`succeedAlertPTag-${targetIpAddress}`);
        var pendingAlert = document.getElementById(`pending-${targetIpAddress}`);
        var pendingAlertHeading = document.getElementById(`pendingAlertHeading-${targetIpAddress}`);
        var pendingAlertPTag = document.getElementById(`pendingAlertPTag-${targetIpAddress}`);

        // clean previous results
        var outputResultDivs = document.querySelectorAll(`div[name="outputResults-${targetIpAddress}"]`);
        outputResultDivs.forEach((outputResultDiv) => {
            outputResultDiv.style.display = "none";
        });
        
        succeedAlert.style.display = "none";
        succeedAlertHeading.innerText = "";
        succeedAlertPTag.innerText = "";
        errorAlert.style.display = "none";
        errorAlertHeading.innerText = "";
        errorAlertPTag.innerText = "";
        pendingAlert.style.display = "";
        pendingAlertHeading.innerText = "Status: Pending";
        pendingAlertPTag.innerText = `Executing the selected attack function on target ${targetIpAddress}...`;
        createToast("Pending", `Executing the selected attack function on target ${targetIpAddress}...`);
    });
}

async function displayNoResults(targetIpAddresses) {
    targetIpAddresses.forEach((targetIpAddress) => {
        var errorAlert = document.getElementById(`error-${targetIpAddress}`);
        var errorAlertHeading = document.getElementById(`failedAlertHeading-${targetIpAddress}`);
        var errorAlertPTag = document.getElementById(`failedAlertPTag-${targetIpAddress}`);
        var succeedAlert = document.getElementById(`succeed-${targetIpAddress}`);
        var succeedAlertHeading = document.getElementById(`succeedAlertHeading-${targetIpAddress}`);
        var succeedAlertPTag = document.getElementById(`succeedAlertPTag-${targetIpAddress}`);
        var pendingAlert = document.getElementById(`pending-${targetIpAddress}`);
        var pendingAlertHeading = document.getElementById(`pendingAlertHeading-${targetIpAddress}`);
        var pendingAlertPTag = document.getElementById(`pendingAlertPTag-${targetIpAddress}`);
        
        succeedAlert.style.display = "none";
        succeedAlertHeading.innerText = "";
        succeedAlertPTag.innerText = "";
        errorAlert.style.display = "";
        errorAlertHeading.innerText = "Status: Failed";
        errorAlertPTag.innerText = `The executed attack function on target ${targetIpAddress} produced no results...`;
        pendingAlert.style.display = "none";
        pendingAlertHeading.innerText = "";
        pendingAlertPTag.innerText = "";
        createToast("Failed", `The executed attack function on target ${targetIpAddress} produced no results...`);
    });
}

async function displayFailedResults(targetIpAddress, responseStatus, message) {
    var errorAlert = document.getElementById(`error-${targetIpAddress}`);
    var errorAlertHeading = document.getElementById(`failedAlertHeading-${targetIpAddress}`);
    var errorAlertPTag = document.getElementById(`failedAlertPTag-${targetIpAddress}`);
    var succeedAlert = document.getElementById(`succeed-${targetIpAddress}`);
    var succeedAlertHeading = document.getElementById(`succeedAlertHeading-${targetIpAddress}`);
    var succeedAlertPTag = document.getElementById(`succeedAlertPTag-${targetIpAddress}`);
    var pendingAlert = document.getElementById(`pending-${targetIpAddress}`);
    var pendingAlertHeading = document.getElementById(`pendingAlertHeading-${targetIpAddress}`);
    var pendingAlertPTag = document.getElementById(`pendingAlertPTag-${targetIpAddress}`);

    succeedAlert.style.display = "none";
    succeedAlertHeading.innerText = "";
    succeedAlertPTag.innerText = "";
    errorAlertHeading.innerText = `Status: ${responseStatus}`;
    errorAlertPTag.innerText = message;
    errorAlert.style.display = "";
    pendingAlert.style.display = "none";
    pendingAlertHeading.innerText = "";
    pendingAlertPTag.innerText = "";
    createToast(responseStatus, message);
}

async function displaySucceedResults(targetIpAddress, responseStatus, message, result) {
    var errorAlert = document.getElementById(`error-${targetIpAddress}`);
    var errorAlertHeading = document.getElementById(`failedAlertHeading-${targetIpAddress}`);
    var errorAlertPTag = document.getElementById(`failedAlertPTag-${targetIpAddress}`);
    var succeedAlert = document.getElementById(`succeed-${targetIpAddress}`);
    var succeedAlertHeading = document.getElementById(`succeedAlertHeading-${targetIpAddress}`);
    var succeedAlertPTag = document.getElementById(`succeedAlertPTag-${targetIpAddress}`);
    var pendingAlert = document.getElementById(`pending-${targetIpAddress}`);
    var pendingAlertHeading = document.getElementById(`pendingAlertHeading-${targetIpAddress}`);
    var pendingAlertPTag = document.getElementById(`pendingAlertPTag-${targetIpAddress}`);

    errorAlert.style.display = "none";
    errorAlertHeading.innerText = "";
    errorAlertPTag.innerText = "";
    pendingAlert.style.display = "none";
    pendingAlertHeading.innerText = "";
    pendingAlertPTag.innerText = "";
    succeedAlertHeading.innerText = `Status: ${responseStatus}`;
    succeedAlertPTag.innerText = message;
    succeedAlert.style.display = "";
    createToast(responseStatus, message);

    var responseCodeBlock = document.getElementById(`response-${targetIpAddress}`);
    responseCodeBlock.innerText = result;
}

async function resetResult(targetIpAddress) {
    var resultPreElement = document.getElementById(`resultPreElement-${targetIpAddress}`);
    resultPreElement.style.display = "";

    var passwordCracking = document.getElementById(`passwordCracking-${targetIpAddress}`);
    var passwordCrackingTable = document.getElementById(`passwordCrackingTable-${targetIpAddress}`);
    var passwordCrackingDropDownSelect = document.getElementById(`passwordCrackingDropDown-${targetIpAddress}`);
    passwordCracking.style.display = "none";
    passwordCrackingDropDownSelect.innerHTML = "";
    passwordCrackingTable.innerHTML = "";

    var kerberoastingResultDiv = document.getElementById(`kerberoastingResult-${targetIpAddress}`);
    var kerberoastingResultDropDownSelect = document.getElementById(`kerberoastingResultDropDown-${targetIpAddress}`);
    var kerberoastingResultTable = document.getElementById(`kerberoastingResultTable-${targetIpAddress}`);
    kerberoastingResultDiv.style.display = "none";
    kerberoastingResultDropDownSelect.innerHTML = "";
    kerberoastingResultTable.innerHTML = "";

    var silverTicketExportTicketResultDiv = document.getElementById(`silverTicketExportTicketResult-${targetIpAddress}`);
    var silverTicketExportTicketResultDropDownSelect = document.getElementById(`silverTicketExportTicketResultDropDown-${targetIpAddress}`);
    var silverTicketExportTicketResultTable = document.getElementById(`silverTicketExportTicketResultTable-${targetIpAddress}`);
    silverTicketExportTicketResultDiv.style.display = "none";
    silverTicketExportTicketResultDropDownSelect.innerHTML = "";
    silverTicketExportTicketResultTable.innerHTML = "";

    var passTheTicketResultDiv = document.getElementById(`passTheTicketResult-${targetIpAddress}`);
    var passTheTicketResultDropDownSelect = document.getElementById(`passTheTicketResultDropDown-${targetIpAddress}`);
    var passTheTicketResultTable = document.getElementById(`passTheTicketResultTable-${targetIpAddress}`);
    passTheTicketResultDiv.style.display = "none";
    passTheTicketResultDropDownSelect.innerHTML = "";
    passTheTicketResultTable.innerHTML = "";

    var silverTicketPttResultDiv = document.getElementById(`silverTicketPttResult-${targetIpAddress}`);
    var silverTicketPttResultDropDownSelect = document.getElementById(`silverTicketPttResultDropDown-${targetIpAddress}`);
    var silverTicketPttResultTable = document.getElementById(`silverTicketPttResultTable-${targetIpAddress}`);
    silverTicketPttResultDiv.style.display = "none";
    silverTicketPttResultDropDownSelect.innerHTML = "";
    silverTicketPttResultTable.innerHTML = "";

    var goldenTicketExportTicketResultDiv = document.getElementById(`goldenTicketExportTicketResult-${targetIpAddress}`);
    var goldenTicketExportTicketResultDropDownSelect = document.getElementById(`goldenTicketExportTicketResultDropDown-${targetIpAddress}`);
    var goldenTicketExportTicketResultTable = document.getElementById(`goldenTicketExportTicketResultTable-${targetIpAddress}`);
    goldenTicketExportTicketResultDiv.style.display = "none";
    goldenTicketExportTicketResultDropDownSelect.innerHTML = "";
    goldenTicketExportTicketResultTable.innerHTML = "";

    var goldenTicketPttResultDiv = document.getElementById(`goldenTicketPttResult-${targetIpAddress}`);
    var goldenTicketPttResultDropDownSelect = document.getElementById(`goldenTicketPttResultDropDown-${targetIpAddress}`);
    var goldenTicketPttResultTable = document.getElementById(`goldenTicketPttResultTable-${targetIpAddress}`);
    goldenTicketPttResultDiv.style.display = "none";
    goldenTicketPttResultDropDownSelect.innerHTML = "";
    goldenTicketPttResultTable.innerHTML = "";
}

async function displayCredentialDumpingResult(targetIpAddress, result) {
    var resultPreElement = document.getElementById(`resultPreElement-${targetIpAddress}`);
    var passwordCracking = document.getElementById(`passwordCracking-${targetIpAddress}`);
    var passwordCrackingTable = document.getElementById(`passwordCrackingTable-${targetIpAddress}`);
    var passwordCrackingDropDownSelect = document.getElementById(`passwordCrackingDropDown-${targetIpAddress}`);

    var regexPattern = /Username:\s(.*)[\s\S]*?Domain:\s(.*)[\s\S]*?Cleartext\spassword.*:\s(.*)[\s\S]*?NTLM\shash:\s(.*)/g;
    var passwordCrackingAccountMatches = [];
    let match;
    while ((match = regexPattern.exec(result["message"][targetIpAddress]["result"])) !== null) {
        var username = match[1];
        var domain = match[2];
        var clearTextPassword = match[3];

        var isCracked;
        if (clearTextPassword === "(No cleartext password)" || clearTextPassword === "(No cleartext password and unable to crack the NTLM hash)") {
            isCracked = false;
        } else {
            isCracked = true;
        }

        var ntlmHash = match[4];
        passwordCrackingAccountMatches.push({ username, domain, clearTextPassword, ntlmHash, isCracked });
    }

    if (passwordCrackingAccountMatches.length === 0) {
        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", "none");
        newOptionElement.innerText = "(No accounts have been found)";
        passwordCrackingDropDownSelect.appendChild(newOptionElement);
        return;
    }

    /*
    <thead class="table-info">
      <tr>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Description</th>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Value</th>
      </tr>
    </thead>
    */
    // Create the thead element
    var thead = document.createElement("thead");
    thead.setAttribute("class", "table-info");

    // Create the tr element
    var theadTr = document.createElement("tr");

    // Create and append the th elements to the tr element
    var thead1 = document.createElement("th");
    thead1.setAttribute("scope", "col");
    thead1.setAttribute("class", "text-center col-4");
    thead1.setAttribute("style", "vertical-align: top;");
    thead1.textContent = "Description";
    theadTr.appendChild(thead1);

    var thead2 = document.createElement("th");
    thead2.setAttribute("scope", "col");
    thead2.setAttribute("class", "text-center col-4");
    thead2.setAttribute("style", "vertical-align: top;");
    thead2.textContent = "Value";
    theadTr.appendChild(thead2);

    // Append the tr element to the thead element
    thead.appendChild(theadTr);

    passwordCrackingTable.appendChild(thead);

    passwordCrackingAccountMatches.forEach((account) => {
        var isFirstResult = false;
        if (account === passwordCrackingAccountMatches[0]) { isFirstResult = true; }

        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", account.username);
        newOptionElement.innerText = `Account: ${account.username} (Domain: ${account.domain})`;
        passwordCrackingDropDownSelect.appendChild(newOptionElement);

        /*
        <tbody name="passwordCrackingTableBody-{ targetIpAddress }" style="display: none;">
          <tr>
            <th scope="row">Cleartext Password:<br>(Cracked Password Legend: <span class="bg-success text-white px-2">password</span>)</th>
            <td><input type="text" class="form-control" disabled></td>
          </tr>
          <tr>
            <th scope="row">NTLM Password Hash:</th>
            <td><input type="text" class="form-control" disabled></td>
          </tr>
        </tbody>
        */
        // Create the <tbody> element
        const tbody = document.createElement("tbody");
        tbody.setAttribute("name", `passwordCrackingTableBody-${targetIpAddress}`);
        tbody.dataset.username = account.username;
        if (isFirstResult) {
            tbody.style.display = "";
        } else {
            tbody.style.display = "none";
        }

        // Create the first <tr> element
        const tr1 = document.createElement("tr");

        // Create the first <th> element
        const th1 = document.createElement("th");
        th1.setAttribute("scope", "row");
        th1.innerHTML =
          'Cleartext Password:<br>(Cracked Password Legend: <span class="bg-success text-white px-2">password</span>)';

        // Create the first <td> element
        const td1 = document.createElement("td");

        // Create the first <input> element
        const input1 = document.createElement("input");
        input1.setAttribute("type", "text");
        if (account.isCracked) {
            input1.setAttribute("class", "form-control bg-success text-white");
        } else {
            input1.setAttribute("class", "form-control");
        }

        input1.disabled = true;
        input1.value = account.clearTextPassword;

        // Append the <input> element to the <td> element
        td1.appendChild(input1);

        // Append the <th> and <td> elements to the first <tr> element
        tr1.appendChild(th1);
        tr1.appendChild(td1);

        // Create the second <tr> element
        const tr2 = document.createElement("tr");

        // Create the second <th> element
        const th2 = document.createElement("th");
        th2.setAttribute("scope", "row");
        th2.innerHTML = "NTLM Password Hash:";

        // Create the second <td> element
        const td2 = document.createElement("td");

        // Create the second <input> element
        const input2 = document.createElement("input");
        input2.setAttribute("type", "text");
        input2.setAttribute("class", "form-control");
        input2.disabled = true;
        input2.value = account.ntlmHash;

        // Append the <input> element to the <td> element
        td2.appendChild(input2);

        // Append the <th> and <td> elements to the second <tr> element
        tr2.appendChild(th2);
        tr2.appendChild(td2);

        // Append the <tr> elements to the <tbody> element
        tbody.appendChild(tr1);
        tbody.appendChild(tr2);

        // Append the <tbody> element to the parent element
        passwordCrackingTable.appendChild(tbody);
    });

    resultPreElement.style.display = "none";
    passwordCracking.style.display = "";
}

async function displayKerberoastingResult(targetIpAddress, result) {
    var resultPreElement = document.getElementById(`resultPreElement-${targetIpAddress}`);
    var kerberoastingResultDiv = document.getElementById(`kerberoastingResult-${targetIpAddress}`);
    var kerberoastingResultDropDownSelect = document.getElementById(`kerberoastingResultDropDown-${targetIpAddress}`);
    var kerberoastingResultTable = document.getElementById(`kerberoastingResultTable-${targetIpAddress}`);

    var regexPattern = /Service account username:\s(.*)\s\(Service:\s(.*)\)\s+Cleartext\spassword\s\((.*)\):?\s?(.*)/g;
    var kerberoastingResultAccountMatches = [];
    let match;
    while ((match = regexPattern.exec(result["message"][targetIpAddress]["result"])) !== null) {
        var username = match[1];
        var service = match[2];

        var isCracked;
        var clearTextPassword;
        if (match[3] === "The ticket is cracked") {
            clearTextPassword = match[4];
            isCracked = true;
        } else {
            clearTextPassword = `(${match[3]})`;
            isCracked = false;
        }

        kerberoastingResultAccountMatches.push({ username, service, clearTextPassword, isCracked });
    }

    if (kerberoastingResultAccountMatches.length === 0) {
        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", "none");
        newOptionElement.innerText = "(No service accounts have been found)";
        kerberoastingResultDropDownSelect.appendChild(newOptionElement);
        return;
    }

    /*
    <thead class="table-info">
      <tr>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Description</th>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Value</th>
      </tr>
    </thead>
    */
    // Create the thead element
    var thead = document.createElement("thead");
    thead.setAttribute("class", "table-info");

    // Create the tr element
    var theadTr = document.createElement("tr");

    // Create and append the th elements to the tr element
    var thead1 = document.createElement("th");
    thead1.setAttribute("scope", "col");
    thead1.setAttribute("class", "text-center col-4");
    thead1.setAttribute("style", "vertical-align: top;");
    thead1.textContent = "Description";
    theadTr.appendChild(thead1);

    var thead2 = document.createElement("th");
    thead2.setAttribute("scope", "col");
    thead2.setAttribute("class", "text-center col-4");
    thead2.setAttribute("style", "vertical-align: top;");
    thead2.textContent = "Value";
    theadTr.appendChild(thead2);

    // Append the tr element to the thead element
    thead.appendChild(theadTr);

    kerberoastingResultTable.appendChild(thead);

    kerberoastingResultAccountMatches.forEach((account) => {
        var isFirstResult = false;
        if (account === kerberoastingResultAccountMatches[0]) { isFirstResult = true; }

        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", account.username);
        newOptionElement.innerText = `Username: ${account.username} (Service: ${account.service})`;
        kerberoastingResultDropDownSelect.appendChild(newOptionElement);

        /*
        <tbody name="kerberoastingResultTableBody-{ targetIpAddress }" style="display: none;">
          <tr>
            <th scope="row">Cleartext Password:<br>(Cracked Password Legend: <span class="bg-success text-white px-2">password</span>)</th>
            <td><input type="text" class="form-control" disabled></td>
          </tr>
          <tr>
            <th scope="row">Export the TGS Ticket:</th>
            <td><a href="/api/exportTgsTicket/kerberoasting/username" target="_blank"><button type="button" class="btn btn-secondary form-control">Click Me To Export the TGS Ticket</button></a></td>
          </tr>
        </tbody>
        */
        // Create the <tbody> element
        const tbody = document.createElement("tbody");
        tbody.setAttribute("name", `kerberoastingResultTableBody-${targetIpAddress}`);
        tbody.dataset.username = account.username;
        if (isFirstResult) {
            tbody.style.display = "";
        } else {
            tbody.style.display = "none";
        }

        // Create the first <tr> element
        const tr1 = document.createElement("tr");

        // Create the first <th> element
        const th1 = document.createElement("th");
        th1.setAttribute("scope", "row");
        th1.innerHTML =
          'Cleartext Password:<br>(Cracked Password Legend: <span class="bg-success text-white px-2">password</span>)';

        // Create the first <td> element
        const td1 = document.createElement("td");

        // Create the first <input> element
        const input1 = document.createElement("input");
        input1.setAttribute("type", "text");
        if (account.isCracked) {
            input1.setAttribute("class", "form-control bg-success text-white");
        } else {
            input1.setAttribute("class", "form-control");
        }

        input1.disabled = true;
        input1.value = account.clearTextPassword;

        // Append the <input> element to the <td> element
        td1.appendChild(input1);

        // Append the <th> and <td> elements to the first <tr> element
        tr1.appendChild(th1);
        tr1.appendChild(td1);

        // Create the second <tr> element
        const tr2 = document.createElement("tr");

        // Create the second <th> element
        const th2 = document.createElement("th");
        th2.setAttribute("scope", "row");
        th2.innerHTML = "Export the TGS Ticket:";

        // Create the second <td> element
        const td2 = document.createElement("td");

        const exportLink = document.createElement("a");
        exportLink.setAttribute("href", `/api/exportTgsTicket/kerberoasting/${account.username}`);
        exportLink.setAttribute("target", "_blank");

        // Create the second <button> element
        const exportButton = document.createElement("button");
        exportButton.setAttribute("type", "button");
        exportButton.setAttribute("class", "btn btn-secondary form-control");
        exportButton.innerText = "Click Me to Export the TGS Ticket";

        // Append the <button> element to the <td> element
        exportLink.appendChild(exportButton);
        td2.appendChild(exportLink);

        // Append the <th> and <td> elements to the second <tr> element
        tr2.appendChild(th2);
        tr2.appendChild(td2);

        // Append the <tr> elements to the <tbody> element
        tbody.appendChild(tr1);
        tbody.appendChild(tr2);

        // Append the <tbody> element to the parent element
        kerberoastingResultTable.appendChild(tbody);
    });

    resultPreElement.style.display = "none";
    kerberoastingResultDiv.style.display = "";
}

async function displayPassTheHashResult(targetIpAddress, result) {
    var resultPreElement = document.getElementById(`resultPreElement-${targetIpAddress}`);
    var passTheHashResultDiv = document.getElementById(`passTheHashResult-${targetIpAddress}`);

    var newAgentId = result["message"][targetIpAddress]["newAgentId"];
    localStorage.setItem("lastestAgentId", newAgentId);

    resultPreElement.style.display = "none";
    passTheHashResultDiv.style.display = "";
}

async function displaySilverTicketPttResult(targetIpAddress, result) {
    var resultPreElement = document.getElementById(`resultPreElement-${targetIpAddress}`);
    var silverTicketPttResultDiv = document.getElementById(`silverTicketPttResult-${targetIpAddress}`);
    var silverTicketPttResultDropDownSelect = document.getElementById(`silverTicketPttResultDropDown-${targetIpAddress}`);
    var silverTicketPttResultTable = document.getElementById(`silverTicketPttResultTable-${targetIpAddress}`);

    var agentIdRegexPattern = /Agent\sID:\s([a-f0-9]+)/;
    var agentIdMatch = result["message"][targetIpAddress]["result"].match(agentIdRegexPattern);
    var agentId = agentIdMatch[1];
    localStorage.setItem("lastestAgentId", agentId);

    var userTickets = {};
    var resultMatches = [];
    var regexPattern = /Ticket\s#(\d+)\s+Username:\s(.*)\s\(Service:\s(.*)\)\s+FQDN\s\(Fully\sQualified\sDomain\sName\):\s(.*)/g;
    let match;
    while ((match = regexPattern.exec(result["message"][targetIpAddress]["result"])) !== null) {
        // var ticketId = match[1];
        var username = match[2];
        var service = match[3];
        var target = match[4];

        userTickets[username] = [];
        resultMatches.push({ username, service, target });
    }

    if (resultMatches.length === 0) {
        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", "none");
        newOptionElement.innerText = "(No accounts have been found)";
        silverTicketPttResultDropDownSelect.appendChild(newOptionElement);
        return;
    }

    resultMatches.forEach((ticket) => {
        var username = ticket["username"];
        var service = ticket["service"];
        var target = ticket["target"];

        userTickets[username].push({ username, service, target });
    });

    /*
    <thead class="table-info">
      <tr>
        <th scope="col" class="text-center col-1" style="vertical-align: top;">Ticket ID</th>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Service</th>
        <th scope="col" class="text-center col-7" style="vertical-align: top;">FQDN (Fully Qualified Domain Name)</th>
      </tr>
    </thead>
    */
    // Create the thead element
    var thead = document.createElement("thead");
    thead.setAttribute("class", "table-info");

    // Create the tr element
    var theadTr = document.createElement("tr");

    // Create and append the th elements to the tr element
    var thead1 = document.createElement("th");
    thead1.setAttribute("scope", "col");
    thead1.setAttribute("class", "text-center col-1");
    thead1.setAttribute("style", "vertical-align: top;");
    thead1.textContent = "Ticket ID";
    theadTr.appendChild(thead1);

    var thead2 = document.createElement("th");
    thead2.setAttribute("scope", "col");
    thead2.setAttribute("class", "text-center col-4");
    thead2.setAttribute("style", "vertical-align: top;");
    thead2.textContent = "Service";
    theadTr.appendChild(thead2);

    var thead3 = document.createElement("th");
    thead3.setAttribute("scope", "col");
    thead3.setAttribute("class", "text-center col-7");
    thead3.setAttribute("style", "vertical-align: top;");
    thead3.textContent = "FQDN (Fully Qualified Domain Name)";
    theadTr.appendChild(thead3);

    // Append the tr element to the thead element
    thead.appendChild(theadTr);

    silverTicketPttResultTable.appendChild(thead);

    var userTicketsEntries = Object.entries(userTickets);
    userTicketsEntries.map( ([username, ticketInformation] = entry) => {
        var isFirstResult = false;
        if (username === Object.keys(userTickets)[0]) { isFirstResult = true; }

        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", username);
        newOptionElement.innerText = `Username: ${username}`;
        silverTicketPttResultDropDownSelect.appendChild(newOptionElement);

        /*
        <tbody name="silverTicketPttResultTableBody-{ targetIpAddress }" style="display: none;">
          <tr>
            <td>{id}</td>
            <td>{service}</td>
            <td>{target}</td>
          </tr>
        </tbody>
        */
        const tbody = document.createElement("tbody");
        tbody.setAttribute("name", `silverTicketPttResultTableBody-${targetIpAddress}`);
        tbody.dataset.username = username;
        if (isFirstResult) {
            tbody.style.display = "";
        } else {
            tbody.style.display = "none";
        }
        ticketInformation.forEach((ticket) => {
            var ticketId = (ticketInformation.indexOf(ticket) + 1).toString();

            const tr1 = document.createElement("tr");

            const td1 = document.createElement("td");
            td1.setAttribute("class", "align-middle");
            td1.innerText = ticketId;
            tr1.appendChild(td1);

            const td2 = document.createElement("td");
            td2.setAttribute("class", "align-middle");
            td2.innerText = ticket.service;
            tr1.appendChild(td2);

            const td3 = document.createElement("td");
            td3.setAttribute("class", "align-middle");
            td3.innerText = ticket.target;
            tr1.appendChild(td3);

            tbody.appendChild(tr1);
        });

        silverTicketPttResultTable.appendChild(tbody);
    });

    resultPreElement.style.display = "none";
    silverTicketPttResultDiv.style.display = "";
}

async function displayExportTicketsResult(targetIpAddress, result, regexPattern) {
    var resultPreElement = document.getElementById(`resultPreElement-${targetIpAddress}`);
    var silverTicketExportTicketResultDiv = document.getElementById(`silverTicketExportTicketResult-${targetIpAddress}`);
    var silverTicketExportTicketResultDropDownSelect = document.getElementById(`silverTicketExportTicketResultDropDown-${targetIpAddress}`);
    var silverTicketExportTicketResultTable = document.getElementById(`silverTicketExportTicketResultTable-${targetIpAddress}`);

    var userTickets = {};
    var ticketMatches = [];
    let match;
    while ((match = regexPattern.exec(result["message"][targetIpAddress]["result"])) !== null) {
        var username = match[1];
        var service = match[2];
        var target = match[3];

        userTickets[username] = [];
        ticketMatches.push({ username, service, target });
    }

    if (ticketMatches.length === 0) {
        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", "none");
        newOptionElement.innerText = "(No service accounts have been found)";
        silverTicketExportTicketResultDropDownSelect.appendChild(newOptionElement);
        return;
    }

    ticketMatches.forEach((ticket) => {
        var username = ticket["username"];
        var service = ticket["service"];
        var target = ticket["target"];

        userTickets[username].push({ username, service, target });
    });

    /*
    <thead class="table-info">
      <tr>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Description</th>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Action</th>
      </tr>
    </thead>
    */
    // Create the thead element
    var thead = document.createElement("thead");
    thead.setAttribute("class", "table-info");

    // Create the tr element
    var theadTr = document.createElement("tr");

    // Create and append the th elements to the tr element
    var thead1 = document.createElement("th");
    thead1.setAttribute("scope", "col");
    thead1.setAttribute("class", "text-center col-4");
    thead1.setAttribute("style", "vertical-align: top;");
    thead1.textContent = "Description";
    theadTr.appendChild(thead1);

    var thead2 = document.createElement("th");
    thead2.setAttribute("scope", "col");
    thead2.setAttribute("class", "text-center col-4");
    thead2.setAttribute("style", "vertical-align: top;");
    thead2.textContent = "Action";
    theadTr.appendChild(thead2);

    // Append the tr element to the thead element
    thead.appendChild(theadTr);

    silverTicketExportTicketResultTable.appendChild(thead);

    var userTicketsEntries = Object.entries(userTickets);
    userTicketsEntries.map( ([username, ticketInformation] = entry) => {
        var isFirstResult = false;
        if (username === Object.keys(userTickets)[0]) { isFirstResult = true; }

        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", username);
        newOptionElement.innerText = `Username: ${username}`;
        silverTicketExportTicketResultDropDownSelect.appendChild(newOptionElement);

        /*
        <tbody name="silverTicketExportTicketResultTableBody-{ targetIpAddress }" style="display: none;">
          <tr>
            <th scope="row">Ticket #{id}<br>Service: {id}<br>FQDN (Fully Qualified Domain Name): {target}</th>
            <td><a href="/api/exportTgsTicket/silverTicket/username" target="_blank"><button type="button" class="btn btn-secondary form-control">Click Me To Export the TGS Ticket</button></a></td>
          </tr>
        </tbody>
        */
        // Create the <tbody> element
        const tbody = document.createElement("tbody");
        tbody.setAttribute("name", `silverTicketExportTicketResultTableBody-${targetIpAddress}`);
        tbody.dataset.username = username;
        if (isFirstResult) {
            tbody.style.display = "";
        } else {
            tbody.style.display = "none";
        }
        ticketInformation.forEach((ticket) => {
            var ticketId = ticketInformation.indexOf(ticket) + 1;

            // Create the second <tr> element
            const tr3 = document.createElement("tr");

            // Create the second <th> element
            const th3 = document.createElement("th");
            th3.setAttribute("scope", "row");
            th3.innerHTML = `Ticket #${ticketId}<br><br>Service: ${ticket.service}<br>FQDN (Fully Qualified Domain Name): ${ticket.target}`;

            // Create the second <td> element
            const td3 = document.createElement("td");
            td3.setAttribute("class", "align-middle");

            const exportLink = document.createElement("a");
            exportLink.setAttribute("href", `/api/exportTgsTicket/silverTicket/${ticket.username}/${ticket.service}`);
            exportLink.setAttribute("target", "_blank");

            // Create the second <button> element
            const exportButton = document.createElement("button");
            exportButton.setAttribute("type", "button");
            exportButton.setAttribute("class", "btn btn-secondary form-control h-100");
            exportButton.innerText = "Click Me to Export the TGS Ticket";

            // Append the <button> element to the <td> element
            exportLink.appendChild(exportButton);
            td3.appendChild(exportLink);

            // Append the <th> and <td> elements to the second <tr> element
            tr3.appendChild(th3);
            tr3.appendChild(td3);

            // Append the <tr> elements to the <tbody> element
            tbody.appendChild(tr3);
        });

        // Append the <tbody> element to the parent element
        silverTicketExportTicketResultTable.appendChild(tbody);
    });

    resultPreElement.style.display = "none";
    silverTicketExportTicketResultDiv.style.display = "";
}

async function displaySilverTicketAttackResult(targetIpAddress, result) {
    var isExportingTickets = !result["message"][targetIpAddress]["result"].includes("Agent ID") ? true : false;
    if (isExportingTickets) {
        var regexPattern = /Service account username:\s(.*)\s\(Service:\s(.*)\)\s+Target:\s(.*)/g;
        displayExportTicketsResult(targetIpAddress, result, regexPattern);
    } else {
        displaySilverTicketPttResult(targetIpAddress, result);
    }
}

async function displayPassTheTicketResult(targetIpAddress, result) {
    var resultPreElement = document.getElementById(`resultPreElement-${targetIpAddress}`);
    var passTheTicketResultDiv = document.getElementById(`passTheTicketResult-${targetIpAddress}`);
    var passTheTicketResultDropDownSelect = document.getElementById(`passTheTicketResultDropDown-${targetIpAddress}`);
    var passTheTicketResultTable = document.getElementById(`passTheTicketResultTable-${targetIpAddress}`);

    var agentIdRegexPattern = /Agent\sID:\s([a-f0-9]+)/;
    var agentIdMatch = result["message"][targetIpAddress]["result"].match(agentIdRegexPattern);
    var agentId = agentIdMatch[1];
    localStorage.setItem("lastestAgentId", agentId);

    var userTickets = {};
    var resultMatches = [];
    var regexPattern = /Ticket\s#(\d+)\s+Username:\s(.*)\s\(Service:\s(.*)\)\s+FQDN\s\(Fully\sQualified\sDomain\sName\):\s(.*)/g;
    let match;
    while ((match = regexPattern.exec(result["message"][targetIpAddress]["result"])) !== null) {
        // var ticketId = match[1];
        var username = match[2];
        var service = match[3];
        var target = match[4];

        userTickets[username] = [];
        resultMatches.push({ username, service, target });
    }

    if (resultMatches.length === 0) {
        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", "none");
        newOptionElement.innerText = "(No accounts have been found)";
        passTheTicketResultDropDownSelect.appendChild(newOptionElement);
        return;
    }

    resultMatches.forEach((ticket) => {
        var username = ticket["username"];
        var service = ticket["service"];
        var target = ticket["target"];

        userTickets[username].push({ username, service, target });
    });

    /*
    <thead class="table-info">
      <tr>
        <th scope="col" class="text-center col-1" style="vertical-align: top;">Ticket ID</th>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Service</th>
        <th scope="col" class="text-center col-7" style="vertical-align: top;">FQDN (Fully Qualified Domain Name)</th>
      </tr>
    </thead>
    */
    // Create the thead element
    var thead = document.createElement("thead");
    thead.setAttribute("class", "table-info");

    // Create the tr element
    var theadTr = document.createElement("tr");

    // Create and append the th elements to the tr element
    var thead1 = document.createElement("th");
    thead1.setAttribute("scope", "col");
    thead1.setAttribute("class", "text-center col-1");
    thead1.setAttribute("style", "vertical-align: top;");
    thead1.textContent = "Ticket ID";
    theadTr.appendChild(thead1);

    var thead2 = document.createElement("th");
    thead2.setAttribute("scope", "col");
    thead2.setAttribute("class", "text-center col-4");
    thead2.setAttribute("style", "vertical-align: top;");
    thead2.textContent = "Service";
    theadTr.appendChild(thead2);

    var thead3 = document.createElement("th");
    thead3.setAttribute("scope", "col");
    thead3.setAttribute("class", "text-center col-7");
    thead3.setAttribute("style", "vertical-align: top;");
    thead3.textContent = "FQDN (Fully Qualified Domain Name)";
    theadTr.appendChild(thead3);

    // Append the tr element to the thead element
    thead.appendChild(theadTr);

    passTheTicketResultTable.appendChild(thead);

    var userTicketsEntries = Object.entries(userTickets);
    userTicketsEntries.map( ([username, ticketInformation] = entry) => {
        var isFirstResult = false;
        if (username === Object.keys(userTickets)[0]) { isFirstResult = true; }

        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", username);
        newOptionElement.innerText = `Username: ${username}`;
        passTheTicketResultDropDownSelect.appendChild(newOptionElement);

        /*
        <tbody name="passTheTicketResultTableBody-{ targetIpAddress }" style="display: none;">
          <tr>
            <td>{id}</td>
            <td>{service}</td>
            <td>{target}</td>
          </tr>
        </tbody>
        */
        const tbody = document.createElement("tbody");
        tbody.setAttribute("name", `passTheTicketResultTableBody-${targetIpAddress}`);
        tbody.dataset.username = username;
        if (isFirstResult) {
            tbody.style.display = "";
        } else {
            tbody.style.display = "none";
        }
        ticketInformation.forEach((ticket) => {
            var ticketId = (ticketInformation.indexOf(ticket) + 1).toString();

            const tr1 = document.createElement("tr");

            const td1 = document.createElement("td");
            td1.setAttribute("class", "align-middle");
            td1.innerText = ticketId;
            tr1.appendChild(td1);

            const td2 = document.createElement("td");
            td2.setAttribute("class", "align-middle");
            td2.innerText = ticket.service;
            tr1.appendChild(td2);

            const td3 = document.createElement("td");
            td3.setAttribute("class", "align-middle");
            td3.innerText = ticket.target;
            tr1.appendChild(td3);

            tbody.appendChild(tr1);
        });

        passTheTicketResultTable.appendChild(tbody);
    });

    resultPreElement.style.display = "none";
    passTheTicketResultDiv.style.display = "";
}

async function displayGoldenTicketPttResult(targetIpAddress, result, agentIdRegexPattern) {
    var resultPreElement = document.getElementById(`resultPreElement-${targetIpAddress}`);
    var goldenTicketPttResultDiv = document.getElementById(`goldenTicketPttResult-${targetIpAddress}`);
    var goldenTicketPttResultDropDownSelect = document.getElementById(`goldenTicketPttResultDropDown-${targetIpAddress}`);
    var goldenTicketPttResultTable = document.getElementById(`goldenTicketPttResultTable-${targetIpAddress}`);

    var agentIdMatch = result["message"][targetIpAddress]["result"].match(agentIdRegexPattern);
    var agentId = agentIdMatch[1];
    localStorage.setItem("lastestAgentId", agentId);

    var userTickets = {};
    var resultMatches = [];
    var regexPattern = /Ticket\s#(\d+)\s+Forged\sGolden\sTicket\sUsername:\s(.*)\s+Domain:\s(.*)\s+NTLM\sHash:\s([a-fA-F0-9]{32})\s+/g;
    let match;
    while ((match = regexPattern.exec(result["message"][targetIpAddress]["result"])) !== null) {
        // var ticketId = match[1];
        var username = match[2];
        var domain = match[3];
        var ntlmHash = match[4];

        userTickets[username] = [];
        resultMatches.push({ username, domain, ntlmHash });
    }

    if (resultMatches.length === 0) {
        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", "none");
        newOptionElement.innerText = "(No accounts have been found)";
        goldenTicketPttResultDropDownSelect.appendChild(newOptionElement);
        return;
    }

    resultMatches.forEach((ticket) => {
        var username = ticket["username"];
        var domain = ticket["domain"];
        var ntlmHash = ticket["ntlmHash"];

        userTickets[username].push({ username, domain, ntlmHash });
    });

    /*
    <thead class="table-info">
      <tr>
        <th scope="col" class="text-center col-1" style="vertical-align: top;">Ticket ID</th>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Domain</th>
        <th scope="col" class="text-center col-7" style="vertical-align: top;">NTLM Hash</th>
      </tr>
    </thead>
    */
    // Create the thead element
    var thead = document.createElement("thead");
    thead.setAttribute("class", "table-info");

    // Create the tr element
    var theadTr = document.createElement("tr");

    // Create and append the th elements to the tr element
    var thead1 = document.createElement("th");
    thead1.setAttribute("scope", "col");
    thead1.setAttribute("class", "text-center col-1");
    thead1.setAttribute("style", "vertical-align: top;");
    thead1.textContent = "Ticket ID";
    theadTr.appendChild(thead1);

    var thead2 = document.createElement("th");
    thead2.setAttribute("scope", "col");
    thead2.setAttribute("class", "text-center col-4");
    thead2.setAttribute("style", "vertical-align: top;");
    thead2.textContent = "Domain";
    theadTr.appendChild(thead2);

    var thead3 = document.createElement("th");
    thead3.setAttribute("scope", "col");
    thead3.setAttribute("class", "text-center col-7");
    thead3.setAttribute("style", "vertical-align: top;");
    thead3.textContent = "NTLM Hash";
    theadTr.appendChild(thead3);

    // Append the tr element to the thead element
    thead.appendChild(theadTr);

    goldenTicketPttResultTable.appendChild(thead);

    var userTicketsEntries = Object.entries(userTickets);
    userTicketsEntries.map( ([username, ticketInformation] = entry) => {
        var isFirstResult = false;
        if (username === Object.keys(userTickets)[0]) { isFirstResult = true; }

        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", username);
        newOptionElement.innerText = `Username: ${username}`;
        goldenTicketPttResultDropDownSelect.appendChild(newOptionElement);

        /*
        <tbody name="goldenTicketPttResultTableBody-{ targetIpAddress }" style="display: none;">
          <tr>
            <td>{id}</td>
            <td>{service}</td>
            <td>{target}</td>
          </tr>
        </tbody>
        */
        const tbody = document.createElement("tbody");
        tbody.setAttribute("name", `goldenTicketPttResultTableBody-${targetIpAddress}`);
        tbody.dataset.username = username;
        if (isFirstResult) {
            tbody.style.display = "";
        } else {
            tbody.style.display = "none";
        }
        ticketInformation.forEach((ticket) => {
            var ticketId = (ticketInformation.indexOf(ticket) + 1).toString();

            const tr1 = document.createElement("tr");

            const td1 = document.createElement("td");
            td1.setAttribute("class", "align-middle");
            td1.innerText = ticketId;
            tr1.appendChild(td1);

            const td2 = document.createElement("td");
            td2.setAttribute("class", "align-middle");
            td2.innerText = ticket.domain;
            tr1.appendChild(td2);

            const td3 = document.createElement("td");
            td3.setAttribute("class", "align-middle");
            td3.innerText = ticket.ntlmHash;
            tr1.appendChild(td3);

            tbody.appendChild(tr1);
        });

        goldenTicketPttResultTable.appendChild(tbody);
    });

    resultPreElement.style.display = "none";
    goldenTicketPttResultDiv.style.display = "";
}

async function displayGoldenTicketExportTicketResult(targetIpAddress, result) {
    var resultPreElement = document.getElementById(`resultPreElement-${targetIpAddress}`);
    var goldenTicketExportTicketResultDiv = document.getElementById(`goldenTicketExportTicketResult-${targetIpAddress}`);
    var goldenTicketExportTicketResultDropDownSelect = document.getElementById(`goldenTicketExportTicketResultDropDown-${targetIpAddress}`);
    var goldenTicketExportTicketResultTable = document.getElementById(`goldenTicketExportTicketResultTable-${targetIpAddress}`);

    var userTickets = {};
    var regexPattern = /Forged Golden Ticket Username:\s(.*)\s+Domain:\s(.*)\s+NTLM Hash:\s([a-fA-F0-9]{32})/g;
    var ticketMatches = [];
    let match;
    while ((match = regexPattern.exec(result["message"][targetIpAddress]["result"])) !== null) {
        var username = match[1];
        var domain = match[2];
        var ntlmHash = match[3];

        userTickets[username] = [];
        ticketMatches.push({ username, domain, ntlmHash });
    }

    if (ticketMatches.length === 0) {
        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", "none");
        newOptionElement.innerText = "(No service accounts have been found)";
        goldenTicketExportTicketResultDropDownSelect.appendChild(newOptionElement);
        return;
    }

    ticketMatches.forEach((ticket) => {
        var username = ticket["username"];
        var domain = ticket["domain"];
        var ntlmHash = ticket["ntlmHash"];

        userTickets[username].push({ username, domain, ntlmHash });
    });

    /*
    <thead class="table-info">
      <tr>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Description</th>
        <th scope="col" class="text-center col-4" style="vertical-align: top;">Action</th>
      </tr>
    </thead>
    */
    // Create the thead element
    var thead = document.createElement("thead");
    thead.setAttribute("class", "table-info");

    // Create the tr element
    var theadTr = document.createElement("tr");

    // Create and append the th elements to the tr element
    var thead1 = document.createElement("th");
    thead1.setAttribute("scope", "col");
    thead1.setAttribute("class", "text-center col-4");
    thead1.setAttribute("style", "vertical-align: top;");
    thead1.textContent = "Description";
    theadTr.appendChild(thead1);

    var thead2 = document.createElement("th");
    thead2.setAttribute("scope", "col");
    thead2.setAttribute("class", "text-center col-4");
    thead2.setAttribute("style", "vertical-align: top;");
    thead2.textContent = "Action";
    theadTr.appendChild(thead2);

    // Append the tr element to the thead element
    thead.appendChild(theadTr);

    goldenTicketExportTicketResultTable.appendChild(thead);

    var userTicketsEntries = Object.entries(userTickets);
    userTicketsEntries.map( ([username, ticketInformation] = entry) => {
        var isFirstResult = false;
        if (username === Object.keys(userTickets)[0]) { isFirstResult = true; }

        var newOptionElement = document.createElement("option");
        newOptionElement.setAttribute("value", username);
        newOptionElement.innerText = `Forged Golden Ticket Username: ${username}`;
        goldenTicketExportTicketResultDropDownSelect.appendChild(newOptionElement);

        /*
        <tbody name="goldenTicketExportTicketResultTableBody-{ targetIpAddress }" style="display: none;">
          <tr>
            <th scope="row">Ticket #{id}<br>Service: {id}<br>FQDN (Fully Qualified Domain Name): {target}</th>
            <td><a href="/api/exportTgsTicket/goldenTicket/username" target="_blank"><button type="button" class="btn btn-secondary form-control">Click Me To Export the TGT Ticket</button></a></td>
          </tr>
        </tbody>
        */
        // Create the <tbody> element
        const tbody = document.createElement("tbody");
        tbody.setAttribute("name", `goldenTicketExportTicketResultTableBody-${targetIpAddress}`);
        tbody.dataset.username = username;
        if (isFirstResult) {
            tbody.style.display = "";
        } else {
            tbody.style.display = "none";
        }
        ticketInformation.forEach((ticket) => {
            var ticketId = ticketInformation.indexOf(ticket) + 1;

            // Create the second <tr> element
            const tr3 = document.createElement("tr");

            // Create the second <th> element
            const th3 = document.createElement("th");
            th3.setAttribute("scope", "row");
            th3.innerHTML = `Ticket #${ticketId}<br><br>Domain: ${ticket.domain}<br>NTLM Hash: ${ticket.ntlmHash}`;

            // Create the second <td> element
            const td3 = document.createElement("td");
            td3.setAttribute("class", "align-middle");

            const exportLink = document.createElement("a");
            exportLink.setAttribute("href", `/api/exportTgsTicket/goldenTicket/${ticket.username}`);
            exportLink.setAttribute("target", "_blank");

            // Create the second <button> element
            const exportButton = document.createElement("button");
            exportButton.setAttribute("type", "button");
            exportButton.setAttribute("class", "btn btn-secondary form-control h-100");
            exportButton.innerText = "Click Me to Export the TGT Ticket";

            // Append the <button> element to the <td> element
            exportLink.appendChild(exportButton);
            td3.appendChild(exportLink);

            // Append the <th> and <td> elements to the second <tr> element
            tr3.appendChild(th3);
            tr3.appendChild(td3);

            // Append the <tr> elements to the <tbody> element
            tbody.appendChild(tr3);
        });

        // Append the <tbody> element to the parent element
        goldenTicketExportTicketResultTable.appendChild(tbody);
    });

    resultPreElement.style.display = "none";
    goldenTicketExportTicketResultDiv.style.display = "";
}

async function displayGoldenTicketResult(targetIpAddress, result) {
    var isExportingTickets = !result["message"][targetIpAddress]["result"].includes("Agent ID") ? true : false;
    if (isExportingTickets) {
        displayGoldenTicketExportTicketResult(targetIpAddress, result);
    } else {
        var agentIdRegexPattern = /Agent\sID:\s([a-f0-9]+)/;
        displayGoldenTicketPttResult(targetIpAddress, result, agentIdRegexPattern);
    }
}

async function displayResults(formattedFunctionName, resultTargetIpAddresses, result) {
    const executeButton = document.getElementById("executeButton");

    resultTargetIpAddresses.forEach((targetIpAddress) => {
        var responseStatus = result["message"][targetIpAddress]["status"];
        if (responseStatus === "Failed") {
            displayFailedResults(targetIpAddress, responseStatus, result["message"][targetIpAddress]["message"])
            executeButton.disabled = false;
            return;
        }
        
        displaySucceedResults(targetIpAddress, responseStatus, result["message"][targetIpAddress]["message"], result["message"][targetIpAddress]["result"]);

        resetResult(targetIpAddress);
        if (formattedFunctionName === "Dump Recently Logged on Accounts\' Password (Mimikatz sekurlsa::logonpasswords)") {
            displayCredentialDumpingResult(targetIpAddress, result);
        } else if (formattedFunctionName === "Extract & Crack Service Accounts' Password (Kerberoasting)") {
            displayKerberoastingResult(targetIpAddress, result);
        } else if (formattedFunctionName === "Password Hash Authentication (Pass-the-Hash)") {
            displayPassTheHashResult(targetIpAddress, result);
        } else if (formattedFunctionName === "Impersonate Service Accounts (Silver Ticket Attack)") {
            displaySilverTicketAttackResult(targetIpAddress, result);
        } else if (formattedFunctionName === "Kerberos Ticket Authentication (Pass-the-Ticket)") {
            displayPassTheTicketResult(targetIpAddress, result);
        } else if (formattedFunctionName === "Domain Admins Persistence (Golden Ticket Attack)") {
            displayGoldenTicketResult(targetIpAddress, result);
        }
    });

    executeButton.disabled = false;
}

async function sendCommand(formattedFunctionName) {
    var targetIpAddresses = [];
    if (formattedFunctionName === "Password Hash Authentication (Pass-the-Hash)") {
        var lateralMovementTargetsCheckboxes = document.querySelectorAll("input[name=lateralMovementTargets]");
        lateralMovementTargetsCheckboxes.forEach((checkbox) => {
            if (checkbox.checked) {
                targetIpAddresses.push(checkbox.value);
            }
        });
    } else {
        targetIpAddresses = getTargetIpAddresses();
    }
    
    await displayPendingMessage(targetIpAddresses);

    var jsonBodyData = prepareJsonData(command, formattedFunctionName);
    const response = await fetch("/api/sendMessage", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: jsonBodyData,
    });
    const result = await response.json();

    await displayResults(formattedFunctionName, targetIpAddresses, result);
}

async function sendAgentCommand(formattedFunctionName) {
    // Pass-the-Hash doesn't support agents
    if (formattedFunctionName === "Password Hash Authentication (Pass-the-Hash)") {
        return;
    }

    var agentIds = getSelectedAgents();

    await displayPendingMessage(agentIds);

    var jsonBodyData = prepareAgentJsonData(command, agentIds, formattedFunctionName);
    const response = await fetch("/api/agentExecuteMimikatzCommand", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: jsonBodyData,
    });
    const result = await response.json();

    await displayResults(formattedFunctionName, agentIds, result);
}