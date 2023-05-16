/*
 *  Copyright 2023 Bundesdruckerei GmbH and/or its affiliates
 *  and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

module.run(($rootScope, $route, Current, RealmLoader) => {
  $rootScope.realmTabs = [];
  $rootScope.usersTabs = [];
  $rootScope.groupsTabs = [];
  $rootScope.menuLinks = [];
  $rootScope.filteredMenuLinks = function () {
    return $rootScope.menuLinks.filter(
      (link) => !link.predicate || link.predicate()
    );
  };

  $route.routes[
    '/realms/:realm/identity-provider-settings/provider/:provider_id/:alias'
  ].controller = 'RealmIdentityProviderCtrlGematikIdp';
});
