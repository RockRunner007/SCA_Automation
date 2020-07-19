xray-reporting
=========================
Generates a report for the last finished scan and downloads the report locally.  The intent is to be wrapped with a jenkins job to facilitate sending the downloaded report to a group of individuals

## Prerequisites

* Python 3.7
* Pipenv

## Usage

Run `pipenv install` to create a virtualenv and install dependencies.

Set the following environment variables:

* XRAY_PROJECT_NAME - Name of the project to pull the most recent scan report

Environment variables can also be specified in a `.env` file local to the script.