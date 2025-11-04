#!/usr/bin/env node
import 'dotenv/config'

interface Config {
	API_TOKEN: string
	PORTS: string
	FIREWALL_ID: string
}

async function main() {
	const config: Config = {
		API_TOKEN: process.env.API_TOKEN || '',
		PORTS: process.env.PORTS || '',
		FIREWALL_ID: process.env.FIREWALL_ID || ''
	}

	// Validate required environment variables
	if (!config.API_TOKEN) {
		console.error('Error: API_TOKEN is not defined. Please set it in .env file or as environment variable.')
		process.exit(1)
	}

	if (!config.PORTS) {
		console.error('Error: PORTS is not defined. Please set it in .env file or as environment variable.')
		process.exit(1)
	}

	if (!config.FIREWALL_ID) {
		console.error('Error: FIREWALL_ID is not defined. Please set it in .env file or as environment variable.')
		process.exit(1)
	}

	console.log('Starting Hetzner Firewall update...')
	console.log(`Firewall ID: ${config.FIREWALL_ID}`)
	console.log(`Ports: ${config.PORTS}`)

	try {
		await updateFirewall(config)
		console.log('✓ Firewall updated successfully!')
	} catch (err: any) {
		console.error('✗ Error:', err.message || err)
		process.exit(1)
	}
}

async function updateFirewall(config: Config) {
	const portList = config.PORTS.split(',')

	// Get IPs
	console.log('Fetching Cloudflare IP ranges...')
	const ipv4List = await fetchList('https://www.cloudflare.com/ips-v4/')
	const ipv6List = await fetchList('https://www.cloudflare.com/ips-v6/')

	console.log(`Found ${ipv4List.length} IPv4 ranges and ${ipv6List.length} IPv6 ranges`)

	// Compile list into rules
	const rules = compileRules([ipv4List, ipv6List], portList)
	console.log(`Created ${rules.length} firewall rules`)

	// Rename the firewall
	const time = new Date()
	console.log('Updating firewall name...')

	const firewallInitResp = await fetch(`https://api.hetzner.cloud/v1/firewalls/${config.FIREWALL_ID}`, {
		method: 'PUT',
		headers: {
			Authorization: 'Bearer ' + config.API_TOKEN,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			name: 'Cloudflare ' + time.toISOString()
		})
	})

	if (firewallInitResp.status !== 200) {
		const errorText = await firewallInitResp.text()
		console.error('Failed to update firewall name:', errorText)
		throw new Error('Failed to update firewall name')
	}

	// Add all the rules
	console.log('Applying firewall rules...')
	const finalResp = await fetch(`https://api.hetzner.cloud/v1/firewalls/${config.FIREWALL_ID}/actions/set_rules`, {
		method: 'POST',
		headers: {
			Authorization: 'Bearer ' + config.API_TOKEN,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			rules
		})
	})

	if (finalResp.status !== 200 && finalResp.status !== 201) {
		const errorText = await finalResp.text()
		console.error('Failed to apply firewall rules:', errorText)
		throw new Error('Failed to apply firewall rules')
	}

	const result = await finalResp.json()
	console.log('Firewall rules applied successfully')
	return result
}

async function fetchList(url: string): Promise<string[]> {
	const resp = await fetch(url)

	if (resp.status !== 200) {
		throw new Error('Failed to fetch ' + url)
	} else {
		const text = await resp.text()
		return text.split(/\r?\n/).filter(line => line.trim() !== '')
	}
}

function compileRules(lists: Array<string[]>, ports: string[]) {
	const builtRules: BuiltRule[] = []
	let ips: string[] = []

	lists.forEach(list => {
		ips = ips.concat(list)
	})

	ports.forEach(port => {
		builtRules.push({
			direction: 'in',
			source_ips: ips,
			protocol: 'tcp',
			port
		})
	})

	return builtRules
}

interface BuiltRule {
	direction: string
	source_ips: string[]
	protocol: string
	port: string
}

main()
