// Lab4.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Queue.h"
#include <fstream>
#include <iostream>
#include "ThreadsHandler.h"
#include <iterator>

int threads_amount = 0;

std::vector<std::string> ReadLines(std::string filename);
std::vector<std::vector<std::string>> GetTasks(std::vector<std::string> source_data);

std::vector<std::string> MergeSort(std::vector<std::vector<std::string>> source)
{
	std::vector<std::string> result_array = source[0];

	for (int k = 1; k < source.size(); k++)
	{
		int i = 0;
		int j = 0;
		std::vector<std::string> first_array = source[k];
		std::vector<std::string> second_array = result_array;
		std::vector<std::string> tmp_array;

		while (first_array.size() > 0 && second_array.size() > 0)
		{
			if (first_array.size() == 0 || second_array.size() == 0)
			{
				break;
			}

			if (first_array.front() < second_array.front())
			{
				tmp_array.push_back(first_array.front());
				first_array.erase(first_array.begin());
				i++;
				continue;
			}

			if (first_array.front() > second_array.front())
			{
				tmp_array.push_back(second_array.front());
				second_array.erase(second_array.begin());
				j++;
				continue;
			}

			if (first_array.front() == second_array.front())
			{
				for (int p = 0; p < 2; p++)
				{
					tmp_array.push_back(first_array.front());
				}

				first_array.erase(first_array.begin());
				second_array.erase(second_array.begin());

				i++;
				j++;
				continue;
			}
		}

		if (first_array.size() > 0)
		{
			while (first_array.size() > 0)
			{
				tmp_array.push_back(first_array.front());
				first_array.erase(first_array.begin());
			}
		} 
		else if (second_array.size() > 0)
		{
			while (second_array.size() > 0)
			{
				tmp_array.push_back(second_array.front());
				second_array.erase(second_array.begin());
			}
		}

		result_array = tmp_array;
	}

	return result_array;
}

int main()
{
	do
	{
		std::cout << std::endl << "Enter threads amount: ";
		std::cin >> threads_amount;
	} while (threads_amount < 1);

	auto input = ReadLines("file.txt");

	auto tasks = GetTasks(input);

	for (int i = 0; i < input.size(); i++)
	{
		std::cout << input[i] << std::endl;
	}

	std::cout << std::endl;

	Queue q(tasks);
	ThreadsHandler tHandler(q, tasks.size());

	auto sorted_tasks = tHandler.Process().Get();

	auto result = MergeSort(sorted_tasks);

	std::cout << "Result: " << std::endl;

	for (int i = 0; i < result.size(); i++)
	{
		std::cout << result[i] << std::endl;
	}

	std::ofstream output_file("output.txt");
	std::ostream_iterator<std::string> output_iterator(output_file, "\n");
	std::copy(result.begin(), result.end(), output_iterator);

	system("pause");

    return 0;
}

std::vector<std::vector<std::string>> GetTasks(std::vector<std::string> source_data)
{
	std::vector<std::vector<std::string>> tasks;
	int tasks_per_thread = ceil((float)source_data.size() / (float)threads_amount);
	
	if (tasks_per_thread == 1)
	{
		tasks_per_thread++;
	}

	for (int i = 0; i < threads_amount - 1; i++)
	{
		std::vector<std::string> task;

		for (int j = 0; j < tasks_per_thread && source_data.size() > 0; j++)
		{
			task.push_back(source_data.front());
			source_data.erase(source_data.begin());
		}

		if (task.size() > 0)
		{
			tasks.push_back(task);
		}
	}

	std::vector<std::string> task;

	while (source_data.size() > 0)
	{
		task.push_back(source_data.front());
		source_data.erase(source_data.begin());
	}

	if (task.size() > 0)
	{
		tasks.push_back(task);
	}

	return tasks;
}

std::vector<std::string> ReadLines(std::string filename)
{
	std::vector<std::string> input_data;

	std::ifstream file(filename);

	if (!file.good())
	{
		return input_data;
	}

	std::string tmp;

	while (std::getline(file, tmp))
	{
		input_data.push_back(tmp);
	}

	file.close();

	return input_data;
}
