import logging, argparse, re, requests, itertools


def group_by_components_with_version(components, component_name, version):
    logger.info("Started executing group_by_components()")

    components_group = {}
    for component in components:
        if (component_name is None or component_name == component['name']) and version == component['version']:
            components_group[component['name']] = components_group.get(component['name'], []) + \
                                                  [{'id': component['id'],
                                                    'version': component['version'],
                                                    'assets': component['assets']}]

    logger.debug("Components Group:" + str(components_group))
    logger.info("Finished executing group_by_components")
    return components_group


def get_components_with_version(host, repository_name, component_name, version):
    logger.info("Started executing get_components()")

    get_components_api, components = host + '/service/rest/beta/components?repository=' + repository_name, []
    try:
        while True:
            response = requests.get(get_components_api)
            response.raise_for_status()

            data = response.json()
            components.append(data['items'])
            continuation_token = data['continuationToken']
            if continuation_token is None:
                break

            get_components_api = host + '/service/rest/beta/components?repository=' + repository_name + '&continuationToken=' + continuation_token

        components = group_by_components_with_version(list(itertools.chain(*components)), component_name, version)
        logger.info("%d components found in repo %s for %s" % (len(components), repository_name, component_name))

        return components
    except requests.exceptions.RequestException as e:
        logger.error("Exception occurred: " + str(e))
        return None


def valid_repository_formats(source_repo_format, destination_repo_format):
    return None != source_repo_format and None != destination_repo_format \
           and source_repo_format == destination_repo_format


def get_repository_format(host, repository_name):
    logger.info("Started executing get_repository_type()")

    get_repositories_api = host + '/service/rest/beta/repositories'
    try:
        response = requests.get(get_repositories_api)
        response.raise_for_status()

        repositories = response.json()
        for repository in repositories:
            logger.debug("Repository: " + str(repository))
            if repository['name'] == repository_name:
                logger.debug("Repository Name match found")
                return repository['format']

        logger.warning("No repository found with given name: " + str(repository_name))
    except requests.exceptions.RequestException as e:
        logger.error("Exception occurred: " + str(e))

    return None


def validate_args(args):
    logger.info("Started executing validate_args()")

    args['host'] = args['host'].strip('/')
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    logger.info("validate_args function execution finished")
    return re.match(regex, args['host'])


def parse_args():
    logger.info("Started executing parse_args()")

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--source-repo', help="Repository from which artifact should be copied/moved",
                        required=True)
    parser.add_argument('-c', '--component', help="Name of the component which has to be copied/moved")
    parser.add_argument('--component-version', help="Version of the component which has to be copied/moved",
                        required=True)
    parser.add_argument('-d', '--destination-repo', help="Repository to which artifact should be copied/moved",
                        default='ArtifactsBackup')
    parser.add_argument('--host', help="Host address of nexus repository", default="http://192.168.113.192:15921")
    parser.add_argument('-u', '--username', help="Username of the nexus repository admin", default="admin")
    parser.add_argument('-p', '--password', help="Password of the nexus repository admin", default="admin123")

    logger.info("parse_args function execution finished")
    return vars(parser.parse_args())


def main():
    logger.info("Started executing main function")

    args = parse_args()
    logger.debug("Arguments parsed are: " + str(args))

    args_valid = validate_args(args)
    if not args_valid:
        logger.error("Arguments passed are not valid. Use -h for help")
        return

    source_repo_format = get_repository_format(args['host'], args['source_repo'])
    destination_repo_format = get_repository_format(args['host'], args['destination_repo'])
    if not valid_repository_formats(source_repo_format, destination_repo_format):
        logger.info("Repository Format is not Valid. Returning execution from here!")
        return

    logger.debug("Source Repo {} format: {}".format(args['source_repo'], source_repo_format))
    logger.debug("Destination Repo {} format: {}".format(args['destination_repo'], destination_repo_format))

    components = get_components_with_version(args['host'], args['source_repo'], args['component'],
                                             args['component_version'])
    logger.debug(components)

    logger.info("Main function execution finished.")


def init_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


if __name__ == '__main__':
    logger = init_logger()
    logger.info("Logger Initialized...Calling main function")
    main()
    logger.info("Returned from main execution. Ending Program!")
