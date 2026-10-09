# T12 polling race regression

Status: TESTS_READY — controller execution pending.

Author: gpt-6.1-sol, high reasoning. Assigned files only: tests/console_polling.test.cjs and this report. No product changes, shell commands, tests, Git operations, installations, services, or helpers were run by this worker.

The single dependency-free Node built-in test executes the real, unmodified security_lab/static/console.js in node:vm. It supplies only the DOM methods/properties used by that script, deferred HTTP response/JSON promises, and a controlled polling callback. The real rendering code builds the observed DOM. A mutation observation records any live-only evidence becoming visible while the offline domain is selected, including a transient stale render.

Scenario: initial live request remains pending; select offline and tick polling; release the HTTP response while JSON remains pending; tick again; release live JSON. Assert no stale visible evidence and exactly one immediate offline request before any further interval tick. Attempt another tick and same-domain change while offline is pending, then release offline response/JSON and assert selected domain, rendered attempt domain, rendered alert evidence, successful connection state, and a maximum of one active response/JSON lifetime.

Controller command: node --test tests/console_polling.test.cjs

Expected red on existing F1: “live evidence became visible while offline was selected”. The prescribed M4-review requestedDomain guard and serialized follow-up should satisfy this case. This worker makes no passing or red-phase execution claim; controller records actual command output.

Development verification limitation: this test requires a local Node installation (controller reported Node 22.14.0). It adds no npm dependency, package manifest, project runtime, or Docker requirement. The minimal DOM does not validate browser layout or a full browser event implementation; browser checks remain T20.

Context7 resolved /websites/nodejs_latest-v22_x_api (official, High reputation) and queried standalone CommonJS node:test and VM context execution separately. Sources: https://nodejs.org/docs/latest-v22.x/api/test.json and https://nodejs.org/docs/latest-v22.x/api/vm.json.

Controller red: Node1 failed206.65ms, stale live evidence observed. Controller green after prescribedD27 product fix: Node1 passed107.78ms; no test changes. Actual command node --test tests/console_polling.test.cjs.
