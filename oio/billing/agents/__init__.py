# Copyright (C) 2025 OVH SAS
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


def _create_account_billing_agent(conf, logger):
    from .account_billing_agent import AccountBillingAgent

    return AccountBillingAgent(conf, logger=logger)


def _create_early_delete_billing_agent(conf, logger):
    from .early_delete_agent import EarlyDeleteAgent

    return EarlyDeleteAgent(conf, logger=logger)


def agent_factory(conf, logger):
    agents = {
        "account": _create_account_billing_agent,
        "early-delete": _create_early_delete_billing_agent,
    }
    agent_type = conf.get("agent_type", "account")

    if agent_type not in agents:
        raise NotImplementedError(f"Agent '{agent_type}' not supported")

    return agents[agent_type](conf, logger=logger)
