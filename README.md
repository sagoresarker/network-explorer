# Network Explorer API

This codebase provides a network exploration API service designed to facilitate various network-related functionalities. The API includes endpoints for traceroute, health checks, and journey tracking, allowing users to analyze network paths and performance.

## Features

- **Traceroute**: Trace the path packets take to a specified domain, providing insights into each hop along the way.
- **Health Check**: Verify the operational status of the API service.
- **Journey Tracking**: Collect detailed information about the network journey, including DNS resolution and connection times.

## Usage

This API service is intended for use in personal projects, such as the portfolio website [sagoresarker.me](http://sagoresarker.me). It can be integrated to provide users with network exploration options, enhancing their experience and understanding of network performance.

## Getting Started

1. Clone the repository.
2. Install the necessary dependencies.
3. Run the application using Docker or directly via Go.
4. Access the API endpoints at `http://localhost:8090`.

## Endpoint Structure

For details on the available endpoints and their request formats, please refer to the [test.http](test.http) file included in the repository.
