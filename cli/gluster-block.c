/*
  Copyright (c) 2016 Red Hat, Inc. <http://www.redhat.com>
  This file is part of gluster-block.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/


# include  "common.h"
# include  "block.h"
# include  "config.h"


# define  GB_CREATE_HELP_STR  "gluster-block create <volname/blockname> "\
                                "[ha <count>] [auth <enable|disable>] "\
                                "[prealloc <full|no>] <HOST1[,HOST2,...]> "\
                                "<size> [--json*]"

# define  GB_DELETE_HELP_STR  "gluster-block delete <volname/blockname> [force] [--json*]"
# define  GB_MODIFY_HELP_STR  "gluster-block modify <volname/blockname> "\
                               "<auth enable|disable> [--json*]"
# define  GB_GMODIFY_HELP_STR "gluster-block gmodify <volname> auth "\
                              "[enable <username> <password> | disable] [--json*]\n"
# define  GB_INFO_HELP_STR    "gluster-block info <volname/blockname> [--json*]"
# define  GB_LIST_HELP_STR    "gluster-block list <volname> [--json*]"


# define  GB_ARGCHECK_OR_RETURN(argcount, count, cmd, helpstr)        \
          do {                                                        \
            if (argcount != count) {                                  \
              MSG("Inadequate arguments for %s:\n%s\n", cmd, helpstr);\
              return -1;                                              \
            }                                                         \
          } while(0)

# define  GB_DEFAULT_SECTOR_SIZE  512

extern const char *argp_program_version;

typedef enum clioperations {
  CREATE_CLI = 1,
  LIST_CLI   = 2,
  INFO_CLI   = 3,
  DELETE_CLI = 4,
  MODIFY_CLI = 5,
  GMODIFY_CLI = 6
} clioperations;


static int
glusterBlockCliRPC_1(void *cobj, clioperations opt)
{
  CLIENT *clnt = NULL;
  int ret = -1;
  int sockfd = -1;
  struct sockaddr_un saun = {0,};
  blockCreateCli *create_obj;
  blockDeleteCli *delete_obj;
  blockInfoCli *info_obj;
  blockListCli *list_obj;
  blockModifyCli *modify_obj;
  blockGModifyCli *gmodify_obj;
  blockResponse reply = {0,};
  char          errMsg[2048] = {0};


  if (strlen(GB_UNIX_ADDRESS) > SUN_PATH_MAX) {
    snprintf (errMsg, sizeof (errMsg), "%s: path length is more than "
              "SUN_PATH_MAX: (%zu > %zu chars)", GB_UNIX_ADDRESS,
              strlen(GB_UNIX_ADDRESS), SUN_PATH_MAX);
    goto out;
  }

  if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    snprintf (errMsg, sizeof (errMsg), "%s: socket creation failed (%s)",
              GB_UNIX_ADDRESS, strerror (errno));
    goto out;
  }

  saun.sun_family = AF_UNIX;
  strcpy(saun.sun_path, GB_UNIX_ADDRESS);

  if (connect(sockfd, (struct sockaddr *) &saun,
              sizeof(struct sockaddr_un)) < 0) {
    if (errno == ENOENT || errno == ECONNREFUSED) {
      snprintf (errMsg, sizeof (errMsg), "Connection failed. Please check if "
                "gluster-block daemon is operational.");
    } else {
      snprintf (errMsg, sizeof (errMsg), "%s: connect failed (%s)",
                GB_UNIX_ADDRESS, strerror (errno));
    }
    goto out;
  }

  clnt = clntunix_create((struct sockaddr_un *) &saun,
                         GLUSTER_BLOCK_CLI, GLUSTER_BLOCK_CLI_VERS,
                         &sockfd, 0, 0);
  if (!clnt) {
    snprintf (errMsg, sizeof (errMsg), "%s, unix addr %s",
              clnt_spcreateerror("client create failed"), GB_UNIX_ADDRESS);
    goto out;
  }

  switch(opt) {
  case CREATE_CLI:
    create_obj = cobj;
    if (block_create_cli_1(create_obj, &reply, clnt) != RPC_SUCCESS) {
      LOG("cli", GB_LOG_ERROR,
          "%sblock %s create on volume %s with hosts %s failed\n",
          clnt_sperror(clnt, "block_create_cli_1"), create_obj->block_name,
          create_obj->volume, create_obj->block_hosts);
      goto out;
    }
    break;
  case DELETE_CLI:
    delete_obj = cobj;
    if (block_delete_cli_1(delete_obj, &reply, clnt) != RPC_SUCCESS) {
      LOG("cli", GB_LOG_ERROR, "%sblock %s delete on volume %s failed",
          clnt_sperror(clnt, "block_delete_cli_1"),
          delete_obj->block_name, delete_obj->volume);
      goto out;
    }
    break;
  case INFO_CLI:
    info_obj = cobj;
    if (block_info_cli_1(info_obj, &reply, clnt) != RPC_SUCCESS) {
      LOG("cli", GB_LOG_ERROR, "%sblock %s info on volume %s failed",
          clnt_sperror(clnt, "block_info_cli_1"),
          info_obj->block_name, info_obj->volume);
      goto out;
    }
    break;
  case LIST_CLI:
    list_obj = cobj;
    if (block_list_cli_1(list_obj, &reply, clnt) != RPC_SUCCESS) {
      LOG("cli", GB_LOG_ERROR, "%sblock list on volume %s failed",
          clnt_sperror(clnt, "block_list_cli_1"), list_obj->volume);
      goto out;
    }
    break;
  case MODIFY_CLI:
    modify_obj = cobj;
    if (block_modify_cli_1(modify_obj, &reply, clnt) != RPC_SUCCESS) {
      LOG("cli", GB_LOG_ERROR, "%sblock modify on volume %s failed",
          clnt_sperror(clnt, "block_modify_cli_1"), modify_obj->volume);
      goto out;
    }
    break;
  case GMODIFY_CLI:
    gmodify_obj = cobj;
    if (block_gmodify_cli_1(gmodify_obj, &reply, clnt) != RPC_SUCCESS) {
      LOG("cli", GB_LOG_ERROR, "%sglobal modify failed",
          clnt_sperror(clnt, "block_gmodify_cli_1"));
      goto out;
    }
    break;
  }

 out:
  if (reply.out) {
    ret = reply.exit;
    MSG("%s", reply.out);
  } else if (errMsg[0]) {
    LOG("cli", GB_LOG_ERROR, "%s", errMsg);
    MSG("%s\n", errMsg);
  } else {
    MSG("%s\n", "Did not receive any response from gluster-block daemon."
        " Please check log files to find the reason");
    ret = -1;
  }

  if (clnt) {
    if (reply.out && !clnt_freeres(clnt, (xdrproc_t)xdr_blockResponse,
                                   (char *)&reply)) {
      LOG("cli", GB_LOG_ERROR, "%s",
          clnt_sperror(clnt, "clnt_freeres failed"));
    }
    clnt_destroy (clnt);
  }

  if (sockfd != -1) {
    close (sockfd);
  }

  return ret;
}


static void
glusterBlockHelp(void)
{
  MSG("%s",
      PACKAGE_NAME" ("PACKAGE_VERSION")\n"
      "usage:\n"
      "  gluster-block <command> <volname[/blockname]> [<args>] [--json*]\n"
      "\n"
      "commands:\n"
      "  create  <volname/blockname> [ha <count>]\n"
      "                              [auth <enable|disable>]\n"
      "                              [prealloc <full|no>]\n"
      "                              <host1[,host2,...]> <size>\n"
      "        create block device [defaults: ha 1, auth disable, prealloc no, size in bytes]\n"
      "\n"
      "  list    <volname>\n"
      "        list available block devices.\n"
      "\n"
      "  info    <volname/blockname>\n"
      "        details about block device.\n"
      "\n"
      "  delete  <volname/blockname> [force]\n"
      "        delete block device.\n"
      "\n"
      "  modify  <volname/blockname> <auth enable|disable>\n"
      "        modify block device.\n"
      "\n"
      "  gmodify <volname> auth [enable <username> <password> | disable]\n"
      "        modify gluster's auth\n"
      "\n"
      "  help\n"
      "        show this message and exit.\n"
      "\n"
      "  version\n"
      "        show version info and exit.\n"
      "\n"
      "supported JSON formats:\n"
      "  --json|--json-plain|--json-spaced|--json-pretty\n"
      );
}

static bool
glusterBlockIsNameAcceptable (char *name)
{
  int i = 0;
  if (!name || strlen(name) == 0)
    return FALSE;
  for (i = 0; i < strlen(name); i++) {
    if (!isalnum (name[i]) && (name[i] != '_') && (name[i] != '-'))
      return FALSE;
  }
  return TRUE;
}

static int
glusterBlockParseVolumeBlock(char *volumeblock, char *volume, char *block,
                             char *helpstr, char *op)
{
  int ret = -1;
  size_t len = 0;
  char *sep = NULL;

  /* part before '/' is the volume name */
  sep = strchr(volumeblock, '/');
  if (!sep) {
    MSG("argument '<volname/blockname>'(%s) is incorrect\n",
        volumeblock);
    MSG("%s\n", helpstr);
    LOG("cli", GB_LOG_ERROR, "%s failed while parsing <volname/blockname>", op);
    goto out;
  }
  len = sep - volumeblock;
  if (len >= 255 || strlen(sep+1) >= 255) {
    MSG("%s\n", "Both volname and blockname should be less than 255 "
        "characters long");
    MSG("%s\n", helpstr);
    LOG("cli", GB_LOG_ERROR, "%s failed while parsing <volname/blockname>", op);
    goto out;
  }
  strncpy(volume, volumeblock, len);
  /* part after / is blockname */
  strncpy(block, sep+1, strlen(sep+1));
  if (!glusterBlockIsNameAcceptable (volume)) {
    MSG("volume name(%s) should contain only aplhanumeric,'-' "
        "and '_' characters\n", volume);
    goto out;
  }
  if (!glusterBlockIsNameAcceptable (block)) {
    MSG("block name(%s) should contain only aplhanumeric,'-' "
        "and '_' characters\n", block);
    goto out;
  }
  ret = 0;
 out:
  return ret;
}

static int
glusterBlockModify(int argcount, char **options, int json)
{
  size_t optind = 2;
  blockModifyCli mobj = {0, };
  int ret = -1;


  GB_ARGCHECK_OR_RETURN(argcount, 5, "modify", GB_MODIFY_HELP_STR);

  mobj.json_resp = json;

  if (glusterBlockParseVolumeBlock (options[optind++], mobj.volume,
                                    mobj.block_name, GB_MODIFY_HELP_STR,
                                    "modify")) {
    goto out;
  }

  /* if auth given then collect status which is next by 'auth' arg */
  if (!strcmp(options[optind], "auth")) {
    optind++;
    ret = convertStringToTrillianParse(options[optind++]);
    if(ret >= 0) {
      mobj.auth_mode = ret;
    } else {
      MSG("%s\n", "'auth' option is incorrect");
      MSG("%s\n", GB_MODIFY_HELP_STR);
      LOG("cli", GB_LOG_ERROR, "Modify failed while parsing argument "
                               "to auth  for <%s/%s>",
                               mobj.volume, mobj.block_name);
      goto out;
    }
  }

  ret = glusterBlockCliRPC_1(&mobj, MODIFY_CLI);
  if (ret) {
    LOG("cli", GB_LOG_ERROR,
        "failed getting info of block %s on volume %s",
        mobj.block_name, mobj.volume);
  }

 out:

  return ret;
}

static int
glusterBlockGModify(int argcount, char **options, int json)
{
  size_t optind = 2;
  blockGModifyCli mobj = {0, };
  int ret = -1;


  mobj.json_resp = json;

  strcpy(mobj.volume, options[optind++]);

  if (!strcmp(options[optind], "auth")) {
    optind++;

    if (!strcmp(options[optind], "enable")) {
      optind++;
      mobj.auth_mode = true;
      strcpy(mobj.username, options[optind++]);
      strcpy(mobj.password, options[optind]);
    } else if (!strcmp(options[optind], "disable")) {
      mobj.auth_mode = false;
      mobj.username[0] = '\0';
      mobj.password[0] = '\0';
    } else {
      MSG("%s\n", "'auth' option is incorrect");
      MSG("%s\n", GB_GMODIFY_HELP_STR);
      LOG("cli", GB_LOG_ERROR, "GModify failed while parsing argument "
                               "to auth for <%s>", options[optind]);
      goto out;
    }

    ret = glusterBlockCliRPC_1(&mobj, GMODIFY_CLI);
    if (ret) {
      LOG("cli", GB_LOG_ERROR,
          "failed to setting global auth the cluster:%d", ret);
    }
  }

 out:

  return ret;
}

static int
glusterBlockCreate(int argcount, char **options, int json)
{
  size_t optind = 2;
  int ret = -1;
  ssize_t sparse_ret;
  blockCreateCli cobj = {0, };


  if (argcount <= optind) {
    MSG("Inadequate arguments for create:\n%s\n", GB_CREATE_HELP_STR);
    return -1;
  }
  cobj.json_resp = json;

  /* default mpath */
  cobj.mpath = 1;

  if (glusterBlockParseVolumeBlock (options[optind++], cobj.volume,
                                    cobj.block_name, GB_CREATE_HELP_STR,
                                    "create")) {
    goto out;
  }

  if (argcount - optind >= 2) {  /* atleast 2 needed */
    /* if ha given then collect count which is next by 'ha' arg */
    if (!strcmp(options[optind], "ha")) {
      optind++;
      sscanf(options[optind++], "%u", &cobj.mpath);
    }
  }

  if (argcount - optind >= 2) {  /* atleast 2 needed */
    /* if auth given then collect boolean which is next by 'auth' arg */
    if (!strcmp(options[optind], "auth")) {
      optind++;
      ret = convertStringToTrillianParse(options[optind++]);
      if(ret >= 0) {
        cobj.auth_mode = ret;
      } else {
        MSG("%s\n", "'auth' option is incorrect");
        MSG("%s\n", GB_CREATE_HELP_STR);
        LOG("cli", GB_LOG_ERROR, "Create failed while parsing argument "
                                 "to auth  for <%s/%s>",
                                 cobj.volume, cobj.block_name);
        goto out;
      }
    }
  }

  if (argcount - optind >= 2) {  /* atleast 2 needed */
    /* if prealloc given then collect boolean which is next by 'prealloc' arg */
    if (!strcmp(options[optind], "prealloc")) {
      optind++;
      ret = convertStringToTrillianParse(options[optind++]);
      if(ret >= 0) {
        cobj.prealloc = ret;
      } else {
        MSG("%s\n", "'prealloc' option is incorrect");
        MSG("%s\n", GB_CREATE_HELP_STR);
        LOG("cli", GB_LOG_ERROR, "Create failed while parsing argument "
                                 "to prealloc  for <%s/%s>",
                                 cobj.volume, cobj.block_name);
        goto out;
      }
    }
  }

  if (argcount - optind < 2) {  /* left with servers and size so 2 */
    MSG("Inadequate arguments for create:\n%s\n", GB_CREATE_HELP_STR);
    LOG("cli", GB_LOG_ERROR,
        "failed creating block %s on volume %s with hosts %s",
        cobj.block_name, cobj.volume, cobj.block_hosts);
    goto out;
  }

  /* next arg to 'ha count' will be servers */
  if (GB_STRDUP(cobj.block_hosts, options[optind++]) < 0) {
    LOG("cli", GB_LOG_ERROR, "failed while parsing servers for block <%s/%s>",
        cobj.volume, cobj.block_name);
    goto out;
  }

  /* last arg will be size */
  sparse_ret = glusterBlockParseSize("cli", options[optind]);
  if (sparse_ret < 0) {
    MSG("%s\n", "'<size>' is incorrect");
    MSG("%s\n", GB_CREATE_HELP_STR);
    LOG("cli", GB_LOG_ERROR, "failed while parsing size for block <%s/%s>",
        cobj.volume, cobj.block_name);
    goto out;
  } else if (sparse_ret < GB_DEFAULT_SECTOR_SIZE) {
    MSG("minimum acceptable block size is %d bytes\n", GB_DEFAULT_SECTOR_SIZE);
    LOG("cli", GB_LOG_ERROR, "minimum acceptable block size is %d bytes <%s/%s>",
        GB_DEFAULT_SECTOR_SIZE, cobj.volume, cobj.block_name);
    goto out;
  }
  cobj.size = sparse_ret;  /* size is unsigned long long */

  ret = glusterBlockCliRPC_1(&cobj, CREATE_CLI);
  if (ret) {
    LOG("cli", GB_LOG_ERROR,
        "failed creating block %s on volume %s with hosts %s",
        cobj.block_name, cobj.volume, cobj.block_hosts);
  }

 out:
  GB_FREE(cobj.block_hosts);

  return ret;
}


static int
glusterBlockList(int argcount, char **options, int json)
{
  blockListCli cobj = {0};
  int ret = -1;


  GB_ARGCHECK_OR_RETURN(argcount, 3, "list", GB_LIST_HELP_STR);
  cobj.json_resp = json;

  strcpy(cobj.volume, options[2]);

  ret = glusterBlockCliRPC_1(&cobj, LIST_CLI);
  if (ret) {
    LOG("cli", GB_LOG_ERROR, "failed listing blocks from volume %s",
        cobj.volume);
  }

  return ret;
}


static int
glusterBlockDelete(int argcount, char **options, int json)
{
  blockDeleteCli cobj = {0};
  int ret = -1;


  if (argcount < 3 || argcount > 4) {
    MSG("Inadequate arguments for delete:\n%s\n", GB_DELETE_HELP_STR);
      return -1;
  }

  if (argcount == 4) {
    if (strcmp(options[3], "force")) {
      MSG("unknown option '%s' for delete:\n%s\n", options[3], GB_DELETE_HELP_STR);
      return -1;
    } else {
      cobj.force = true;
    }
  }

  cobj.json_resp = json;

  if (glusterBlockParseVolumeBlock (options[2], cobj.volume,
                                    cobj.block_name, GB_DELETE_HELP_STR,
                                    "delete")) {
    goto out;
  }

  ret = glusterBlockCliRPC_1(&cobj, DELETE_CLI);
  if (ret) {
    LOG("cli", GB_LOG_ERROR, "failed deleting block %s on volume %s",
        cobj.block_name, cobj.volume);
  }

 out:

  return ret;
}


static int
glusterBlockInfo(int argcount, char **options, int json)
{
  blockInfoCli cobj = {0};
  int ret = -1;


  GB_ARGCHECK_OR_RETURN(argcount, 3, "info", GB_INFO_HELP_STR);
  cobj.json_resp = json;

  if (glusterBlockParseVolumeBlock (options[2], cobj.volume,
                                    cobj.block_name, GB_INFO_HELP_STR,
                                    "info")) {
    goto out;
  }

  ret = glusterBlockCliRPC_1(&cobj, INFO_CLI);
  if (ret) {
    LOG("cli", GB_LOG_ERROR,
        "failed getting info of block %s on volume %s",
        cobj.block_name, cobj.volume);
  }

 out:

  return ret;
}


static int
glusterBlockParseArgs(int count, char **options)
{
  int ret = 0;
  size_t opt = 0;
  int json = GB_JSON_NONE;


  opt = glusterBlockCLIOptEnumParse(options[1]);
  if (!opt || opt >= GB_CLI_OPT_MAX) {
    MSG("Unknown option: %s\n", options[1]);
    return -1;
  }

  if (opt > 0 && opt < GB_CLI_HELP) {
          json = jsonResponseFormatParse (options[count-1]);
          if (json == GB_JSON_MAX) {
            MSG("expecting '--json*', got '%s'\n",
                options[count-1]);
            return -1;
          } else if (json != GB_JSON_NONE) {
                  count--;/*Commands don't need to handle json*/
          }
  }

  while (1) {
    switch (opt) {
    case GB_CLI_CREATE:
      ret = glusterBlockCreate(count, options, json);
      if (ret && ret != EEXIST) {
        LOG("cli", GB_LOG_ERROR, "%s", FAILED_CREATE);
      }
      goto out;

    case GB_CLI_LIST:
      ret = glusterBlockList(count, options, json);
      if (ret) {
        LOG("cli", GB_LOG_ERROR, "%s", FAILED_LIST);
      }
      goto out;

    case GB_CLI_INFO:
      ret = glusterBlockInfo(count, options, json);
      if (ret) {
        LOG("cli", GB_LOG_ERROR, "%s", FAILED_INFO);
      }
      goto out;

    case GB_CLI_MODIFY:
      ret = glusterBlockModify(count, options, json);
      if (ret) {
        LOG("cli", GB_LOG_ERROR, "%s", FAILED_MODIFY);
      }
      goto out;

    case GB_CLI_GMODIFY:
      ret = glusterBlockGModify(count, options, json);
      if (ret) {
        LOG("cli", GB_LOG_ERROR, "%s", FAILED_GMODIFY);
      }
      goto out;

    case GB_CLI_DELETE:
      ret = glusterBlockDelete(count, options, json);
      if (ret) {
        LOG("cli", GB_LOG_ERROR, "%s", FAILED_DELETE);
      }
      goto out;

    case GB_CLI_HELP:
    case GB_CLI_HYPHEN_HELP:
    case GB_CLI_USAGE:
    case GB_CLI_HYPHEN_USAGE:
      glusterBlockHelp();
      goto out;

    case GB_CLI_VERSION:
    case GB_CLI_HYPHEN_VERSION:
      MSG("%s\n", argp_program_version);
      goto out;
    }
  }

 out:
  return ret;
}


int
main(int argc, char *argv[])
{
  if (argc <= 1) {
    glusterBlockHelp();
    exit(EXIT_FAILURE);
  }

  if(initLogging()) {
    exit(EXIT_FAILURE);
  }

  return glusterBlockParseArgs(argc, argv);
}
