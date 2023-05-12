/*
 *  Copyright 2023 Bundesdruckerei GmbH and/or its affiliates
 *  and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

function pollAuthenticationStatus({ statusUrl, pollInterval = 1000 }) {
  if (statusUrl) {
    let authenticationStatusIntVal = null;

    authenticationStatusIntVal = setInterval(async () => {
      const response = await fetch(statusUrl);
      const json = await response.json();
      if (
        json.currentStep === "RECEIVED_HBA_DATA" ||
        json.currentStep === "RECEIVED_SMCB_DATA" ||
        json.currentStep === "IDP_ERROR"
      ) {
        clearTimeout(authenticationStatusIntVal);
        location.assign(json.nextStepUrl);
      }
    }, pollInterval);
  }
}

function redirectAfterTimout({ timeoutUrl, timeout }) {
  if (timeoutUrl && timeout) {
    setTimeout(() => {
      location.assign(timeoutUrl);
    }, timeout);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const modal = document.querySelector(".gematik-idp-modal");
  if (modal) {
    document
        .querySelector(".gematik-idp-modal .close")
        .addEventListener("click", function () {
          modal.style.display = "none";
        });
  }

  try {
    const { statusUrl, timeoutUrl, timeout } = JSON.parse(
      document.getElementById("gematikIdpConfiguration").textContent
    );

    pollAuthenticationStatus({ statusUrl });
    redirectAfterTimout({ timeoutUrl, timeout });
  } catch (e) {}
});
