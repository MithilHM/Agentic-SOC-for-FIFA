up:        ## start redis + api + worker
	docker compose up -d redis worker api
seed:      ## start the continuous simulator
	docker compose up -d simulator
demo:      ## run the scripted kill-chain
	docker compose run --rm simulator python -m simulator.scenarios
dash:      ## start the dashboard
	docker compose up -d dashboard
down:
	docker compose down -v
train:
	python -m ml.train_model
test:      ## run the pytest suite in a throwaway container (needs redis up)
	docker compose run --rm api sh -c "pip install -q -r requirements-dev.txt && python -m pytest tests/ -v"
eval:      ## run the LangGraph agent eval harness against labeled incidents
	docker compose run --rm api python -m evals.run_agent_eval
