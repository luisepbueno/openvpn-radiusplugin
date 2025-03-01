/*
 *  radiusplugin -- An OpenVPN plugin for do radius authentication
 *					and accounting.
 *
 *  Copyright (C) 2005 EWE TEL GmbH/Ralf Luebben <ralfluebben@gmx.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "AcctScheduler.h"
#include "PluginContext.h"
#include "RadiusClass/RadiusConfig.h"
#include "Config.h"
#include "radiusplugin.h"
#include "Utils.h"

using namespace std;

/** The constructor of the class.
 * Nothing happens here.
 */

AcctScheduler::AcctScheduler()
{
}

/**The destructor of the class.
 * The user lists are cleared here.
 */
AcctScheduler::~AcctScheduler()
{
	activeuserlist.clear();
	passiveuserlist.clear();
}

/** The method adds an user to the user lists. An user with an acct interim
 * interval is added to the activeuserlist, an user
 * without this interval is added to passiveuserlist.
 * @param user A pointer to an object from the class UserAcct.
 */
void AcctScheduler::addUser(UserAcct *user)
{
	if (user->getAcctInterimInterval() == 0)
	{

		this->passiveuserlist.insert(make_pair(user->getKey(), *user));
	}
	else
	{
		this->activeuserlist.insert(make_pair(user->getKey(), *user));
	}
}

/** The method deletes an user from the user lists. Before
 * the user is deleted the status file is parsed for the sent and received bytes
 * and the stop accounting ticket is send to the server.
 * @param context The plugin context as an object from the class PluginContext.
 * @param user A pointer to an object from the class UserAcct
 */
void AcctScheduler::delUser(PluginContext *context, UserAcct *user)
{

	if (DEBUG(context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: Got accounting data from file, CN: " << user->getCommonname() << " in: " << user->getBytesIn() << " out: " << user->getBytesOut() << ".\n";

	// send the stop ticket
	if (user->sendStopPacket(context) == 0)
	{
		if (DEBUG(context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: Stop packet was sent. CN: " << user->getCommonname() << ".\n";
	}
	else
	{
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: Error on sending stop packet.";
	}

	if (user->getAcctInterimInterval() == 0)
	{
		passiveuserlist.erase(user->getKey());
	}
	else
	{

		activeuserlist.erase(user->getKey());
	}
}

/** The method deletes all users from the user lists. Before
 * the user is deleted the status file is parsed for the sent and received bytes
 * and the stop accounting ticket is send to the server.
 * @param context The plugin context as an object from the class PluginContext.
 */
void AcctScheduler::delallUsers(PluginContext *context)
{
	map<string, UserAcct>::iterator iter1, iter2;
	if (DEBUG(context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: Delete all users.";
	iter1 = activeuserlist.begin();
	iter2 = activeuserlist.end();

	while (iter1 != iter2)
	{
		this->delUser(context, &(iter1->second));
		iter1++;
	}
}

/** The accounting method. When the method is called it
 * searches for users in activeuserlist for users who need an update.
 * If a user is found the sent and received bytes are read from the
 * OpenVpn status file.
 * @param context The plugin context as an object from the class PluginContext.
 */

void AcctScheduler::doAccounting(PluginContext *context)
{
	time_t t;

	uint64_t bytesin = 0, bytesout = 0;
	map<string, UserAcct>::iterator iter1, iter2;

	iter1 = activeuserlist.begin();
	iter2 = activeuserlist.end();

	while (iter1 != iter2)
	{
		// get the time
		time(&t);
		// if the user needs an update
		if (t >= iter1->second.getNextUpdate())
		{
			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: Scheduler: Update for User " << iter1->second.getUsername() << ".\n";

			this->parseStatusFile(context, &bytesin, &bytesout, iter1->second.getStatusFileKey().c_str());
			if (bytesin > 0 && bytesout > 0)
			{
				iter1->second.setBytesIn(bytesin & 0xFFFFFFFF);
				iter1->second.setBytesOut(bytesout & 0xFFFFFFFF);
				iter1->second.setGigaIn(bytesin >> 32);
				iter1->second.setGigaOut(bytesout >> 32);
				iter1->second.sendUpdatePacket(context);

				if (DEBUG(context->getVerbosity()))
					cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: Scheduler: Update packet for User " << iter1->second.getUsername() << " was send.\n";
			}
			else
			{
				cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: Scheduler: Don't update for " << iter1->second.getUsername() << " because of lack of data.\n";
			}

			// calculate the next update
			iter1->second.setNextUpdate(iter1->second.getNextUpdate() + iter1->second.getAcctInterimInterval());
		}
		iter1++;
	}
}

/**The method parses the status file for accounting information. It reads the bytes sent
 * and received from the status file. It finds the values about the commonname. The method will
 * only work if there are no changes in the structure of the status file.
 * The method was tested with OpenVpn 2.0.
 * @param context The plugin context as an object from the class PluginContext.
 * @param bytesin An int pointer for the received bytes.
 * @param bytesout An int pointer for the sent bytes.
 * @param key  A key which identifies the row in the statusfile, it looks like: "commonname,ip:port".
 */
void AcctScheduler::parseStatusFile(PluginContext *context, uint64_t *bytesin, uint64_t *bytesout, string key)
{
	/*
	OpenVPN 2.6 status format
	CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher
	*/

	bool found = false;

	// open the status file to read
	ifstream file(context->conf.getStatusFile().c_str(), ios::in);
	if (file.is_open())
	{
		if (DEBUG(context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: Scheduler: read status file.\n";

		do
		{
			string line;
			getline(file, line);

			vector<string> tokens = tokenize(line, ',');

			if (tokens.size() == 13 && tokens[0] == "CLIENT_LIST")
			{
				string common_name = tokens[1];
				string real_address = tokens[2];
				if (key == common_name + "," + real_address)
				{
					*bytesin = std::stoi(tokens[5]);
					*bytesout = std::stoi(tokens[6]);
					found = true;
				}
			}
		} while (file.eof() == false);

		file.close();

		if (!found)
		{
			cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: No accounting data was found for " << key << " in file " << context->conf.getStatusFile() << endl;
		}
	}
	else
	{
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND-ACCT: Status file " << context->conf.getStatusFile() << " could not be opened." << endl;
	}
}

/** The method finds an user.
 * @param key The commonname of the user to find.
 * @return A poniter to an object of the class UserAcct.
 */
UserAcct *AcctScheduler::findUser(string key)
{
	map<string, UserAcct>::iterator iter;
	iter = activeuserlist.find(key);
	if (iter != activeuserlist.end())
	{
		return &(iter->second);
	}
	iter = passiveuserlist.find(key);
	if (iter != passiveuserlist.end())
	{
		return &(iter->second);
	}

	return NULL;
}
