/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Default constructors ignore errors and return nil in the case of an error.
// This should never happen unless the validation/default setting logic is broken.
func TestDefaultConstructors(t *testing.T) {
	require.NotNil(t, DefaultAuthPreference())
	require.NotNil(t, DefaultClusterConfig())
	require.NotNil(t, DefaultClusterNetworkingConfig())
	require.NotNil(t, DefaultNamespace())
	require.NotNil(t, DefaultSessionRecordingConfig())
	require.NotNil(t, DefaultStaticTokens())
}
