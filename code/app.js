document.getElementById('alert-form').addEventListener('submit', async function(e) {
    e.preventDefault(); // Stop the form from submitting normally

    const responseMessage = document.getElementById('response-message');
    responseMessage.textContent = 'Sending request...';
    responseMessage.className = '';
    const levelInput = document.getElementById('level');

    // Check if the input element exists before adding event listener
    if(levelInput){
        // Should define min and max attributes on the HTML input element
        const min = 1;
        const max = 10;

        levelInput.oninput  = function(){
            let value = parseInt(this.value);

            if(value > max){
                this.value = max;

            }else if(value < min){
                this.value = min;
            }
        }
    }
    // 1. Collect data from the form
    const alertData = {
        rule_id: parseInt(document.getElementById('rule_id').value, 10),
        level: parseInt(document.getElementById('level').value, 10),
        agent_id: document.getElementById('agent_id').value,
        description: document.getElementById('description').value,
        full_log: document.getElementById('full_log').value
    };

    const API_URL = 'http://127.0.0.1:8000/alert';

    try {
        // 2. Send the POST request using the Fetch API
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'accept': 'application/json'
            },
            body: JSON.stringify(alertData)
        });

        // 3. Handle the response
        if (response.status === 201) {
            const result = await response.json();
            responseMessage.className = 'success';
            responseMessage.textContent = `Success! Status ${response.status} Created. Alert processed by backend.`;
            // Optional: Log the full response object
            console.log('API Response:', result);
        } else {
            // Handle 4xx or 5xx errors
            const errorText = await response.text();
            responseMessage.className = 'error';
            responseMessage.textContent = `Error: Status ${response.status}. Message: ${errorText.substring(0, 100)}...`;
            console.error('API Error:', errorText);
        }
    } catch (error) {
        // Handle network errors (e.g., server not running)
        responseMessage.className = 'error';
        responseMessage.textContent = `Network Error: Could not connect to API at ${API_URL}. Ensure your backend server is running.`;
        console.error('Fetch Error:', error);
    }
});