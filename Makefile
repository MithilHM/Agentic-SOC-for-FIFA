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
