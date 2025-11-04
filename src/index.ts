export interface Env {
	WORKER_SECRET: string
	API_TOKEN: string
	PORTS: string
	FIREWALL_ID: string
}

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext) {
		if (typeof env.WORKER_SECRET !== 'undefined' && request.headers.get('Authorization') != env.WORKER_SECRET) {
			return new Response('Unauthorized for manual calls.', {
				status: 403
			})
		}

		try {
			return await handleRequest(env, ctx)
		}
		catch (err: any) {
			return new Response(err.message, { status: 500 })
		}
	},

	async scheduled(env: Env, ctx: ExecutionContext) {
		await handleRequest(env, ctx);
	}

}

async function handleRequest(env: Env, ctx: ExecutionContext) {
	if (env.API_TOKEN === undefined) {
		return new Response('env.API_TOKEN is not defined. Please define it.', {
			status: 403
		})
	}

	console.log('Starting firewall update for ID:', env.FIREWALL_ID)

	const portList = env.PORTS.split(',')

	// get IPs, error if not 200
	console.log('Fetching Cloudflare IP ranges...')
	const ipv4List = await fetchList('https://www.cloudflare.com/ips-v4/')
	const ipv6List = await fetchList('https://www.cloudflare.com/ips-v6/')

	console.log(`Found ${ipv4List.length} IPv4 ranges and ${ipv6List.length} IPv6 ranges`)

	// compile list into rules
	let rules = compileRules([ipv4List, ipv6List], portList)

	console.log(`Created ${rules.length} firewall rules for ports: ${portList.join(', ')}`)

	// rename the firewall
	// error if this fails
	console.log('Updating firewall name...')

	const time = new Date()

	const firewallInitResp = await fetch(`https://api.hetzner.cloud/v1/firewalls/${env.FIREWALL_ID}`, {
		method: 'PUT',
		headers: {
			Authorization: 'Bearer ' + env.API_TOKEN,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			name: 'Cloudflare ' + time.toISOString()
		})
	}
	)

	if (firewallInitResp.status !== 200) {
		console.log('Failed to init Firewall: ' + await firewallInitResp.text())
		throw 'Failed to init Firewall'
	}

	// add all the rules
	console.log('Applying firewall rules...')
	const finalResp = await fetch(`https://api.hetzner.cloud/v1/firewalls/${env.FIREWALL_ID}/actions/set_rules`, {
		method: 'POST',
		headers: {
			Authorization: 'Bearer ' + env.API_TOKEN,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			rules
		})
	}
	)

	if (finalResp.status !== 200 && finalResp.status !== 201) {
		const errorText = await finalResp.text()
		console.log('Failed to apply firewall rules: ' + errorText)
		throw 'Failed to apply firewall rules'
	}

	console.log('Firewall updated successfully!')

	return new Response('Firewall updated successfully', {
		status: 200,
		headers: {
			'Content-Type': 'application/json'
		}
	})
}

async function fetchList(url: string) {
	const resp = await fetch(url)

	if (resp.status !== 200) {
		throw 'Failed to fetch ' + url
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

export interface BuiltRule {
	direction: string
	source_ips: string[]
	protocol: string
	port: string
}