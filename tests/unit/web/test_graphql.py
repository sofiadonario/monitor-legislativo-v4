"""
Unit tests for GraphQL API
Tests GraphQL schema and basic queries

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import pytest
from strawberry import Schema
from web.api.graphql_schema import schema, Query, Mutation
import asyncio


class TestGraphQLSchema:
    """Test GraphQL schema definition"""
    
    def test_schema_creation(self):
        """Test that schema is created successfully"""
        assert isinstance(schema, Schema)
        assert schema.query is Query
        assert schema.mutation is Mutation
    
    def test_query_fields(self):
        """Test that all query fields are defined"""
        query_type = schema.query
        fields = query_type.__strawberry_definition__.fields
        
        expected_fields = [
            'search_propositions',
            'get_proposition',
            'get_analytics',
            'search_authors'
        ]
        
        field_names = [field.name for field in fields]
        for expected in expected_fields:
            assert expected in field_names, f"Missing field: {expected}"
    
    def test_mutation_fields(self):
        """Test that all mutation fields are defined"""
        mutation_type = schema.mutation
        fields = mutation_type.__strawberry_definition__.fields
        
        expected_fields = [
            'track_proposition',
            'export_search_results'
        ]
        
        field_names = [field.name for field in fields]
        for expected in expected_fields:
            assert expected in field_names, f"Missing field: {expected}"


class TestGraphQLQueries:
    """Test GraphQL query execution"""
    
    @pytest.mark.asyncio
    async def test_search_propositions_query(self):
        """Test basic search propositions query"""
        query = '''
            query {
                searchPropositions(query: "test", limit: 5) {
                    propositions {
                        id
                        title
                        source
                    }
                    stats {
                        totalResults
                        sourcesQueried
                    }
                }
            }
        '''
        
        # Execute query
        result = await schema.execute(query)
        
        # Verify no errors
        assert result.errors is None or len(result.errors) == 0
        assert result.data is not None
        
        # Check structure
        assert 'searchPropositions' in result.data
        assert 'propositions' in result.data['searchPropositions']
        assert 'stats' in result.data['searchPropositions']
    
    @pytest.mark.asyncio
    async def test_get_analytics_query(self):
        """Test get analytics query"""
        query = '''
            query {
                getAnalytics {
                    totalPropositions
                    bySource
                    byStatus
                    trends {
                        keyword
                        count
                    }
                }
            }
        '''
        
        result = await schema.execute(query)
        
        assert result.errors is None or len(result.errors) == 0
        assert result.data is not None
        assert 'getAnalytics' in result.data
        
        analytics = result.data['getAnalytics']
        assert 'totalPropositions' in analytics
        assert 'bySource' in analytics
        assert 'byStatus' in analytics
        assert 'trends' in analytics


class TestGraphQLIntegration:
    """Test GraphQL integration with FastAPI"""
    
    def test_graphql_route_import(self):
        """Test that GraphQL routes can be imported"""
        try:
            from web.api.graphql_routes import router, graphql_app
            assert router is not None
            assert graphql_app is not None
        except ImportError as e:
            pytest.fail(f"Failed to import GraphQL routes: {e}")
    
    def test_schema_export(self):
        """Test that schema can be exported as SDL"""
        sdl = str(schema)
        assert "type Query" in sdl
        assert "type Mutation" in sdl
        assert "type Proposition" in sdl
        assert "searchPropositions" in sdl


if __name__ == "__main__":
    # Run basic tests
    print("Testing GraphQL Schema...")
    test_schema = TestGraphQLSchema()
    test_schema.test_schema_creation()
    test_schema.test_query_fields()
    print("✅ Schema tests passed")
    
    print("\nTesting GraphQL Queries...")
    test_queries = TestGraphQLQueries()
    asyncio.run(test_queries.test_search_propositions_query())
    asyncio.run(test_queries.test_get_analytics_query())
    print("✅ Query tests passed")
    
    print("\n🎉 All GraphQL tests passed!")