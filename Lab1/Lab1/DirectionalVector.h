#pragma once

class DirectionalVector
{
	private:
		float accelerate, delta, blow;
		bool isPressed;

	public:
		float speed;

		DirectionalVector();

		void IncreaseSpeed();

		void StartKeyPress();
		void StopKeyPress();

		void ProcessBlow(float);

		float Move();

		bool CanMove();
		bool IsPressed();
		float InvertDirection();
};
