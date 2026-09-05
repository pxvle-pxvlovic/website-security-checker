document.getElementById("scan-form").addEventListener("submit", async function(event){
			event.preventDefault();
			
			const domain = document.getElementById("domain-input").value;
			const apiKey = document.getElementById("api-key-input").value;
			document.getElementById("results").innerHTML = "<p>Scanning...</p>";

			const response = await fetch("http://localhost:8000/scan",{
				method: "POST",
				headers: { 
					"Content-Type": "application/json",
					"X-API-Key": apiKey
				},
				body: JSON.stringify({ domain: domain })
			});

			const data = await response.json();

			let headerIssuesHtml = "";
			for (const issue of data.headers.issues){
				headerIssuesHtml = headerIssuesHtml + "<li>" + issue + "</li>";
			}

			let tlsIssuesHtml = "";
			for (const issue of data.tls.issues){
				tlsIssuesHtml = tlsIssuesHtml + "<li>" + issue + "</li>";
			}

			let emailIssuesHtml = "";
			for (const issue of data.email.issues){
				emailIssuesHtml = emailIssuesHtml + "<li>" + issue + "</li>";
			}


			const resultsDiv = document.getElementById("results");
			resultsDiv.innerHTML = `
				<h2>${data.domain ?? domain}</h2>
				<p>Score: ${data.score} / 3</p>
				<p class="${data.tls.valid ? "status-good" : "status-bad"}">TLS: ${data.tls.valid ? "Valid" : "Issues found"}</p>
				${data.tls.issues.length > 0 ? `<ul>${tlsIssuesHtml}</ul>` : ""}
        		<p class="${data.headers.valid ? "status-good" : "status-bad"}">Headers: ${data.headers.valid ? "All present" : "Missing some"}</p>
        		${data.headers.issues.length > 0 ? `<ul>${headerIssuesHtml}</ul>` : ""}
        		<p class="${data.email.valid ? "status-good" : "status-bad"}">Email (SPF/DMARC): ${data.email.valid ? "Configured" : "Issues found"}</p>
        		${data.email.issues.length > 0 ? `<ul>${emailIssuesHtml}</ul>` : ""}
    		`;
    		const historyResponse = await fetch(`http://localhost:8000/scans/${domain}`, {
    			headers: { "X-API-Key": apiKey }
    		});
    		const historyData = await historyResponse.json();

    		let historyHtml = "";
    		for (const scan of historyData){
    			historyHtml = historyHtml + "<li>" + scan.scanned_at + " - Score: " + scan.score + "</li>";
    		}
    		document.getElementById("results").innerHTML += `<h3>Previous scans</h3><ul class="history-list">${historyHtml}</ul>`;
		});